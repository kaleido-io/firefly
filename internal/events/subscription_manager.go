// Copyright © 2023 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import (
	"context"
	"regexp"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/retry"
	"github.com/hyperledger/firefly/internal/broadcast"
	"github.com/hyperledger/firefly/internal/coreconfig"
	"github.com/hyperledger/firefly/internal/coremsgs"
	"github.com/hyperledger/firefly/internal/data"
	"github.com/hyperledger/firefly/internal/privatemessaging"
	"github.com/hyperledger/firefly/internal/txcommon"
	"github.com/hyperledger/firefly/pkg/core"
	"github.com/hyperledger/firefly/pkg/database"
	"github.com/hyperledger/firefly/pkg/events"
	"github.com/hyperledger/firefly/pkg/leaderelection"
)

type subscription struct {
	definition *core.Subscription

	dispatcherElection chan bool
	eventMatcher       *regexp.Regexp
	messageFilter      *messageFilter
	blockchainFilter   *blockchainFilter
	transactionFilter  *transactionFilter
	topicFilter        *regexp.Regexp
}

type messageFilter struct {
	groupFilter  *regexp.Regexp
	tagFilter    *regexp.Regexp
	authorFilter *regexp.Regexp
}

type blockchainFilter struct {
	nameFilter     *regexp.Regexp
	listenerFilter *regexp.Regexp
}

type transactionFilter struct {
	typeFilter *regexp.Regexp
}

type connection struct {
	id          string
	transport   string
	matcher     events.SubscriptionMatcher
	dispatchers map[fftypes.UUID]*eventDispatcher
	ei          events.Plugin
}

type subscriptionManager struct {
	ctx                       context.Context
	namespace                 string
	enricher                  *eventEnricher
	database                  database.Plugin
	data                      data.Manager
	txHelper                  txcommon.Helper
	eventNotifier             *eventNotifier
	broadcast                 broadcast.Manager
	messaging                 privatemessaging.Manager
	transports                map[string]events.Plugin
	connections               map[string]*connection
	mux                       sync.Mutex
	maxSubs                   uint64
	durableSubs               map[fftypes.UUID]*subscription
	cancelCtx                 func()
	newOrUpdatedSubscriptions chan *fftypes.UUID
	deletedSubscriptions      chan *fftypes.UUID
	retry                     retry.Retry
	leaderElection            leaderelection.Plugin
}

func newSubscriptionManager(ctx context.Context, ns string, enricher *eventEnricher, di database.Plugin, dm data.Manager, en *eventNotifier, bm broadcast.Manager, pm privatemessaging.Manager, txHelper txcommon.Helper, transports map[string]events.Plugin, le leaderelection.Plugin) (*subscriptionManager, error) {
	ctx, cancelCtx := context.WithCancel(ctx)
	sm := &subscriptionManager{
		ctx:                       ctx,
		namespace:                 ns,
		enricher:                  enricher,
		database:                  di,
		data:                      dm,
		transports:                transports,
		connections:               make(map[string]*connection),
		durableSubs:               make(map[fftypes.UUID]*subscription),
		newOrUpdatedSubscriptions: make(chan *fftypes.UUID),
		deletedSubscriptions:      make(chan *fftypes.UUID),
		maxSubs:                   uint64(config.GetUint(coreconfig.SubscriptionMax)),
		cancelCtx:                 cancelCtx,
		eventNotifier:             en,
		broadcast:                 bm, // optional
		messaging:                 pm, // optional
		txHelper:                  txHelper,
		leaderElection:            le,
		retry: retry.Retry{
			InitialDelay: config.GetDuration(coreconfig.SubscriptionsRetryInitialDelay),
			MaximumDelay: config.GetDuration(coreconfig.SubscriptionsRetryMaxDelay),
			Factor:       config.GetFloat64(coreconfig.SubscriptionsRetryFactor),
		},
	}

	for _, ei := range sm.transports {
		if err := ei.SetHandler(sm.namespace, &boundCallbacks{sm: sm, ei: ei}); err != nil {
			return nil, err
		}
	}

	return sm, nil
}

func (sm *subscriptionManager) start() error {
	fb := database.SubscriptionQueryFactory.NewFilter(sm.ctx)
	filter := fb.And().Limit(sm.maxSubs)
	persistedSubs, _, err := sm.database.GetSubscriptions(sm.ctx, sm.namespace, filter)
	if err != nil {
		return err
	}
	sm.mux.Lock()
	defer sm.mux.Unlock()
	for _, subDef := range persistedSubs {
		newSub, err := sm.parseSubscriptionDef(sm.ctx, subDef)
		if err != nil {
			// Warn and continue startup
			log.L(sm.ctx).Warnf("Failed to reload subscription %s:%s [%s]: %s", subDef.Namespace, subDef.Name, subDef.ID, err)
			continue
		}
		sm.durableSubs[*subDef.ID] = newSub
		for _, conn := range sm.connections {
			sm.matchSubToConnLocked(conn, newSub)
		}
	}
	log.L(sm.ctx).Infof("Subscription manager started - loaded %d durable subscriptions", len(sm.durableSubs))
	go sm.subscriptionEventListener()
	return nil
}

func (sm *subscriptionManager) subscriptionEventListener() {
	for {
		select {
		case id := <-sm.newOrUpdatedSubscriptions:
			go sm.newOrUpdatedDurableSubscription(id)
		case id := <-sm.deletedSubscriptions:
			go sm.deletedDurableSubscription(id)
		case <-sm.ctx.Done():
			return
		}
	}
}

func (sm *subscriptionManager) newOrUpdatedDurableSubscription(id *fftypes.UUID) {
	var subDef *core.Subscription
	err := sm.retry.Do(sm.ctx, "retrieve subscription", func(attempt int) (retry bool, err error) {
		subDef, err = sm.database.GetSubscriptionByID(sm.ctx, sm.namespace, id)
		return err != nil, err // indefinite retry
	})
	if err != nil || subDef == nil {
		// either the context was cancelled (so we're closing), or the subscription no longer exists
		log.L(sm.ctx).Infof("Unable to process new subscription event for id=%s (%v)", id, err)
		return
	}

	log.L(sm.ctx).Infof("Created subscription %s:%s [%s]", subDef.Namespace, subDef.Name, subDef.ID)

	newSub, err := sm.parseSubscriptionDef(sm.ctx, subDef)
	if err != nil {
		// Swallow this, as the subscription is simply invalid
		log.L(sm.ctx).Errorf("Subscription rejected by subscription manager: %s", err)
		return
	}

	// Now we're ready to update our locked state, adding this subscription to our
	// in-memory table, and creating any missing dispatchers
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if existingSub, ok := sm.durableSubs[*subDef.ID]; ok {
		if existingSub.definition.Updated.Equal(newSub.definition.Updated) {
			log.L(sm.ctx).Infof("Subscription already active")
			return
		}
		// Need to close the old one
		loaded, dispatchers := sm.closeDurableSubscriptionLocked(subDef.ID)
		if loaded {
			// Outside the lock, close out the active dispatchers
			sm.mux.Unlock()
			for _, dispatcher := range dispatchers {
				dispatcher.close()
			}
			sm.mux.Lock()
		}
	}
	sm.durableSubs[*subDef.ID] = newSub
	for _, conn := range sm.connections {
		sm.matchSubToConnLocked(conn, newSub)
	}
}

func (sm *subscriptionManager) closeDurableSubscriptionLocked(id *fftypes.UUID) (bool, []*eventDispatcher) {
	var dispatchers []*eventDispatcher
	// Remove it from the list of durable subs (if there)
	_, loaded := sm.durableSubs[*id]
	if loaded {
		delete(sm.durableSubs, *id)
		// Find any active dispatchers, while we're in the lock, and remove them
		for _, conn := range sm.connections {
			dispatcher, ok := conn.dispatchers[*id]
			if ok {
				dispatchers = append(dispatchers, dispatcher)
				delete(conn.dispatchers, *id)
			}
		}
	}
	return loaded, dispatchers
}

func (sm *subscriptionManager) deletedDurableSubscription(id *fftypes.UUID) {
	sm.mux.Lock()
	loaded, dispatchers := sm.closeDurableSubscriptionLocked(id)
	sm.mux.Unlock()

	log.L(sm.ctx).Infof("Cleaning up subscription %s loaded=%t dispatchers=%d", id, loaded, len(dispatchers))

	// Outside the lock, close out the active dispatchers
	for _, dispatcher := range dispatchers {
		dispatcher.close()
	}
	// Delete the offsets, as the durable subscriptions are gone
	err := sm.database.DeleteOffset(sm.ctx, core.OffsetTypeSubscription, id.String())
	if err != nil {
		log.L(sm.ctx).Errorf("Failed to cleanup subscription offset: %s", err)
	}
}

func (sm *subscriptionManager) parseSubscriptionDef(ctx context.Context, subDef *core.Subscription) (sub *subscription, err error) {
	filter := subDef.Filter

	transport, ok := sm.transports[subDef.Transport]
	if !ok {
		return nil, i18n.NewError(ctx, coremsgs.MsgUnknownEventTransportPlugin, subDef.Transport)
	}

	if err := transport.ValidateOptions(&subDef.Options); err != nil {
		return nil, err
	}

	var eventFilter *regexp.Regexp
	if filter.Events != "" {
		eventFilter, err = regexp.Compile(filter.Events)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.events", filter.Events)
		}
	}

	var tagFilter *regexp.Regexp
	if filter.DeprecatedTag != "" {
		log.L(ctx).Warnf("Your subscription filter uses the deprecated 'tag' key - please change to 'message.tag' instead")
		tagFilter, err = regexp.Compile(filter.DeprecatedTag)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.tag", filter.DeprecatedTag)
		}
	}

	if filter.Message.Tag != "" {
		tagFilter, err = regexp.Compile(filter.Message.Tag)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.message.tag", filter.Message.Tag)
		}
	}

	var groupFilter *regexp.Regexp
	if filter.DeprecatedGroup != "" {
		log.L(ctx).Warnf("Your subscription filter uses the deprecated 'group' key - please change to 'message.group' instead")
		// set to group filter, will be overwritten by non-deprecated key if both are present
		groupFilter, err = regexp.Compile(filter.DeprecatedGroup)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.group", filter.DeprecatedGroup)
		}
	}

	if filter.Message.Group != "" {
		groupFilter, err = regexp.Compile(filter.Message.Group)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.message.group", filter.Message.Group)
		}
	}

	var topicFilter *regexp.Regexp
	if filter.DeprecatedTopics != "" {
		log.L(ctx).Warnf("Your subscription filter uses the deprecated 'topics' key - please change to 'topic' instead")
		// set to topics filter, will be overwritten by non-deprecated key if both are present
		topicFilter, err = regexp.Compile(filter.DeprecatedTopics)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.topics", filter.DeprecatedTopics)
		}
	}

	if filter.Topic != "" {
		topicFilter, err = regexp.Compile(filter.Topic)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.topic", filter.Topic)
		}
	}

	var authorFilter *regexp.Regexp
	if filter.DeprecatedAuthor != "" {
		log.L(ctx).Warnf("Your subscription filter uses the deprecated 'author' key - please change to 'message.author' instead")
		// set to author filter, will be overwritten by non-deprecated key if both are present
		authorFilter, err = regexp.Compile(filter.DeprecatedAuthor)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.author", filter.DeprecatedAuthor)
		}
	}

	if filter.Message.Author != "" {
		authorFilter, err = regexp.Compile(filter.Message.Author)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.message.author", filter.Message.Author)
		}
	}

	sub = &subscription{
		dispatcherElection: make(chan bool, 1),
		definition:         subDef,
		eventMatcher:       eventFilter,
		topicFilter:        topicFilter,
		messageFilter: &messageFilter{
			tagFilter:    tagFilter,
			groupFilter:  groupFilter,
			authorFilter: authorFilter,
		},
	}

	if (filter.BlockchainEvent != core.BlockchainEventFilter{}) {
		var nameFilter *regexp.Regexp
		if filter.BlockchainEvent.Name != "" {
			nameFilter, err = regexp.Compile(filter.BlockchainEvent.Name)
			if err != nil {
				return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.blockchain.name", filter.BlockchainEvent.Name)
			}
		}

		var listenerFilter *regexp.Regexp
		if filter.BlockchainEvent.Listener != "" {
			listenerFilter, err = regexp.Compile(filter.BlockchainEvent.Listener)
			if err != nil {
				return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.blockchain.listener", filter.BlockchainEvent.Listener)
			}
		}

		bf := &blockchainFilter{
			nameFilter:     nameFilter,
			listenerFilter: listenerFilter,
		}
		sub.blockchainFilter = bf
	}

	if (filter.Transaction != core.TransactionFilter{}) {
		var typeFilter *regexp.Regexp
		if filter.Transaction.Type != "" {
			typeFilter, err = regexp.Compile(filter.Transaction.Type)
			if err != nil {
				return nil, i18n.WrapError(ctx, err, coremsgs.MsgRegexpCompileFailed, "filter.transaction.type", filter.Transaction.Type)
			}
		}

		tf := &transactionFilter{
			typeFilter: typeFilter,
		}
		sub.transactionFilter = tf
	}

	return sub, err
}

func (sm *subscriptionManager) close() {
	sm.mux.Lock()
	conns := make([]*connection, 0, len(sm.connections))
	for _, conn := range sm.connections {
		conns = append(conns, conn)
	}
	sm.mux.Unlock()
	for _, conn := range conns {
		sm.connectionClosed(conn.ei, conn.id)
	}
}

func (sm *subscriptionManager) getCreateConnLocked(ei events.Plugin, connID string) *connection {
	conn, ok := sm.connections[connID]
	if !ok {
		conn = &connection{
			id:          connID,
			transport:   ei.Name(),
			dispatchers: make(map[fftypes.UUID]*eventDispatcher),
			ei:          ei,
		}
		sm.connections[connID] = conn
		log.L(sm.ctx).Debugf("Registered connection %s for %s", conn.id, ei.Name())
	}
	return conn
}

func (sm *subscriptionManager) registerConnection(ei events.Plugin, connID string, matcher events.SubscriptionMatcher) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()

	// Check if there are existing dispatchers
	conn := sm.getCreateConnLocked(ei, connID)
	if conn.ei != ei {
		return i18n.NewError(sm.ctx, coremsgs.MsgMismatchedTransport, connID, ei.Name(), conn.ei.Name())
	}

	// Update the matcher for this connection ID
	conn.matcher = matcher

	// Make sure we don't have dispatchers now for any that don't match
	for subID, d := range conn.dispatchers {
		if !d.subscription.definition.Ephemeral && !conn.matcher(d.subscription.definition.SubscriptionRef) {
			d.close()
			delete(conn.dispatchers, subID)
		}
	}
	// Make new dispatchers for all durable subscriptions that match
	for _, sub := range sm.durableSubs {
		sm.matchSubToConnLocked(conn, sub)
	}

	return nil
}

func (sm *subscriptionManager) matchSubToConnLocked(conn *connection, sub *subscription) {
	if conn == nil || sub == nil || sub.definition == nil || conn.matcher == nil {
		log.L(sm.ctx).Warnf("Invalid connection/subscription registered: conn=%+v sub=%+v", conn, sub)
		return
	}
	if conn.transport == sub.definition.Transport && conn.matcher(sub.definition.SubscriptionRef) {
		if _, ok := conn.dispatchers[*sub.definition.ID]; !ok {
			dispatcher := newEventDispatcher(sm.ctx, sm.enricher, conn.ei, sm.database, sm.data, sm.broadcast, sm.messaging, conn.id, sub, sm.eventNotifier, sm.txHelper, sm.leaderElection)
			conn.dispatchers[*sub.definition.ID] = dispatcher
			dispatcher.start()
		}
	}
}

func (sm *subscriptionManager) ephemeralSubscription(ei events.Plugin, connID, namespace string, filter *core.SubscriptionFilter, options *core.SubscriptionOptions) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()

	conn := sm.getCreateConnLocked(ei, connID)

	if conn.ei != ei {
		return i18n.NewError(sm.ctx, coremsgs.MsgMismatchedTransport, connID, ei.Name(), conn.ei.Name())
	}

	subID := fftypes.NewUUID()
	subDefinition := &core.Subscription{
		SubscriptionRef: core.SubscriptionRef{
			ID:        subID,
			Name:      subID.String(),
			Namespace: namespace,
		},
		Transport: ei.Name(),
		Ephemeral: true,
		Filter:    *filter,
		Options:   *options,
		Created:   fftypes.Now(),
	}

	newSub, err := sm.parseSubscriptionDef(sm.ctx, subDefinition)
	if err != nil {
		return err
	}

	// Create the dispatcher, and start immediately
	dispatcher := newEventDispatcher(sm.ctx, sm.enricher, ei, sm.database, sm.data, sm.broadcast, sm.messaging, connID, newSub, sm.eventNotifier, sm.txHelper, sm.leaderElection)
	dispatcher.start()

	conn.dispatchers[*subID] = dispatcher

	log.L(sm.ctx).Infof("Created new %s ephemeral subscription %s:%s for connID=%s", ei.Name(), namespace, subID, connID)

	return nil
}

func (sm *subscriptionManager) connectionClosed(ei events.Plugin, connID string) {
	sm.mux.Lock()
	conn, ok := sm.connections[connID]
	if ok && conn.ei != ei {
		log.L(sm.ctx).Warnf(i18n.ExpandWithCode(sm.ctx, i18n.MessageKey(coremsgs.MsgMismatchedTransport), connID, ei.Name(), conn.ei.Name()))
		sm.mux.Unlock()
		return
	}
	delete(sm.connections, connID)
	sm.mux.Unlock()

	if !ok {
		log.L(sm.ctx).Debugf("Connections already disposed: %s", connID)
		return
	}
	log.L(sm.ctx).Debugf("Closing %d dispatcher(s) for connection '%s'", len(conn.dispatchers), connID)
	for _, d := range conn.dispatchers {
		d.close()
	}
}

func (sm *subscriptionManager) deliveryResponse(ei events.Plugin, connID string, inflight *core.EventDeliveryResponse) {
	sm.mux.Lock()
	var dispatcher *eventDispatcher
	conn, ok := sm.connections[connID]
	if ok && inflight.Subscription.ID != nil {
		dispatcher = conn.dispatchers[*inflight.Subscription.ID]
	}
	if ok && conn.ei != ei {
		err := i18n.NewError(sm.ctx, coremsgs.MsgMismatchedTransport, connID, ei.Name(), conn.ei.Name())
		log.L(sm.ctx).Errorf("Invalid DeliveryResponse callback from plugin: %s", err)
		sm.mux.Unlock()
		return
	}
	if dispatcher == nil {
		err := i18n.NewError(sm.ctx, coremsgs.MsgConnSubscriptionNotStarted, inflight.Subscription.ID)
		log.L(sm.ctx).Errorf("Invalid DeliveryResponse callback from plugin: %s", err)
		sm.mux.Unlock()
		return
	}
	sm.mux.Unlock()
	dispatcher.deliveryResponse(inflight)
}
