// Copyright © 2021 Kaleido, Inc.
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

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type FilteredResult struct {
	Count int64       `json:"count"`
	Total int64       `json:"total"`
	Items interface{} `json:"items"`
}

func main() {
	rate := vegeta.Rate{Freq: 100, Per: time.Second}
	duration := 60 * time.Second

	ff := getFFClient()

	targeter := getPostTargeter()
	attacker := vegeta.NewAttacker()

	var metrics vegeta.Metrics

	for res := range attacker.Attack(targeter, rate, duration, "FF") {
		metrics.Add(res)
	}
	start := time.Now()
	metrics.Close()

	ticker := time.NewTicker(1 * time.Second)
	done := make(chan bool)

	fmt.Println("Waiting for transactions to finish....")
	go func() {
		for {
			<-ticker.C
			pendingCount := GetPendingCount(ff)
			if pendingCount == 0 {
				done <- true
			}
		}
	}()
	<-done

	t := time.Now()
	elapsed := t.Sub(start)

	reporter := vegeta.NewTextReporter(&metrics)
	err := reporter(os.Stdout)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Elapsed time between last sent message and 0 pending transactions: %s\n", elapsed)

}

func getPostTargeter() vegeta.Targeter {
	return func(t *vegeta.Target) error {
		if t == nil {
			return vegeta.ErrNilTarget
		}

		t.Method = "POST"
		t.URL = "http://127.0.0.1:5000/api/v1/namespaces/default/messages/broadcast"

		payload := `{
			"data": [
				{
					"value": {
                        "test": "json"
                    }
                }
			]
		}`

		t.Body = []byte(payload)

		header := http.Header{}
		header.Add("Accept", "application/json")
		header.Add("Content-Type", "application/json")
		t.Header = header

		return nil
	}
}

func GetPendingCount(client *resty.Client) int64 {
	var txs *FilteredResult
	res, err := client.R().
		SetResult(&txs).
		Get("namespaces/default/transactions?count&status=Pending")

	if err != nil || !res.IsSuccess() {
		fmt.Println("Error getting pending count")
	}

	return txs.Count
}

func getFFClient() *resty.Client {
	client := resty.New()
	client.SetHostURL("http://localhost:5000/api/v1")

	return client
}
