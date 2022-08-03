// Copyright © 2022 Kaleido, Inc.
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

package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hyperledger/firefly/test/e2e"
	"github.com/hyperledger/firefly/test/e2e/client"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

type testState struct {
	t                    *testing.T
	startTime            time.Time
	done                 func()
	ws1                  *websocket.Conn
	ws2                  *websocket.Conn
	client1              *client.FireFlyClient
	client2              *client.FireFlyClient
	unregisteredAccounts []interface{}
	namespace            string
	stackName            string
	adminHost1           string
	adminHost2           string
	configFile1          string
	configFile2          string
}

func (m *testState) T() *testing.T {
	return m.t
}

func (m *testState) StartTime() time.Time {
	return m.startTime
}

func (m *testState) Done() func() {
	return m.done
}

func beforeE2ETest(t *testing.T) *testState {
	stackDir := os.Getenv("STACK_DIR")
	if stackDir == "" {
		t.Fatal("STACK_DIR must be set")
	}
	stack := e2e.ReadStack(t)
	stackState := e2e.ReadStackState(t)

	var authHeader1 http.Header
	var authHeader2 http.Header

	httpProtocolClient1 := schemeHTTP
	httpProtocolClient2 := schemeHTTP
	if stack.Members[0].UseHTTPS {
		httpProtocolClient1 = schemeHTTPS
	}
	if stack.Members[1].UseHTTPS {
		httpProtocolClient2 = schemeHTTPS
	}

	member0WithPort := ""
	if stack.Members[0].ExposedFireflyPort != 0 {
		member0WithPort = fmt.Sprintf(":%d", stack.Members[0].ExposedFireflyPort)
	}
	member1WithPort := ""
	if stack.Members[1].ExposedFireflyPort != 0 {
		member1WithPort = fmt.Sprintf(":%d", stack.Members[1].ExposedFireflyPort)
	}

	base1 := fmt.Sprintf("%s://%s%s", httpProtocolClient1, stack.Members[0].FireflyHostname, member0WithPort)
	base2 := fmt.Sprintf("%s://%s%s", httpProtocolClient2, stack.Members[1].FireflyHostname, member1WithPort)
	admin1 := fmt.Sprintf("%s://%s:%d", httpProtocolClient1, stack.Members[0].FireflyHostname, stack.Members[0].ExposedAdminPort)
	admin2 := fmt.Sprintf("%s://%s:%d", httpProtocolClient2, stack.Members[1].FireflyHostname, stack.Members[1].ExposedAdminPort)

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	ts := &testState{
		t:                    t,
		stackName:            stack.Name,
		startTime:            time.Now(),
		client1:              client.NewFireFly(t, base1, namespace),
		client2:              client.NewFireFly(t, base2, namespace),
		unregisteredAccounts: stackState.Accounts[2:],
		namespace:            namespace,
		adminHost1:           admin1,
		adminHost2:           admin2,
		configFile1:          filepath.Join(stackDir, "runtime", "config", "firefly_core_0.yml"),
		configFile2:          filepath.Join(stackDir, "runtime", "config", "firefly_core_1.yml"),
	}

	t.Logf("Blockchain provider: %s", stack.BlockchainProvider)

	if stack.Members[0].Username != "" && stack.Members[0].Password != "" {
		t.Log("Setting auth for user 1")
		ts.client1.Client.SetBasicAuth(stack.Members[0].Username, stack.Members[0].Password)
		authHeader1 = http.Header{
			"Authorization": []string{fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", stack.Members[0].Username, stack.Members[0].Password))))},
		}
	}

	if stack.Members[1].Username != "" && stack.Members[1].Password != "" {
		t.Log("Setting auth for user 2")
		ts.client2.Client.SetBasicAuth(stack.Members[1].Username, stack.Members[1].Password)
		authHeader2 = http.Header{
			"Authorization": []string{fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", stack.Members[1].Username, stack.Members[1].Password))))},
		}
	}

	// If no namespace is set to run tests against, use the default namespace
	if os.Getenv("NAMESPACE") != "" {
		namespace := os.Getenv("NAMESPACE")
		ts.namespace = namespace
	}

	t.Logf("Client 1: " + ts.client1.Client.HostURL)
	t.Logf("Client 2: " + ts.client2.Client.HostURL)
	e2e.PollForUp(t, ts.client1)
	e2e.PollForUp(t, ts.client2)

	eventNames := "message_confirmed|token_pool_confirmed|token_transfer_confirmed|blockchain_event_received|token_approval_confirmed|identity_confirmed"
	queryString := fmt.Sprintf("namespace=%s&ephemeral&autoack&filter.events=%s&changeevents=.*", ts.namespace, eventNames)
	ts.ws1 = ts.client1.WebSocket(t, queryString, authHeader1)
	ts.ws2 = ts.client2.WebSocket(t, queryString, authHeader2)

	ts.done = func() {
		ts.ws1.Close()
		ts.ws2.Close()
		t.Log("WebSockets closed")
	}
	return ts
}
