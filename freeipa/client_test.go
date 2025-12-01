// Copyright © 2022 IN2P3 Computing Centre, IN2P3, CNRS
// Copyright © 2018 Philippe Voinov
//
// Contributor(s): Remi Ferrand <remi.ferrand_at_cc.in2p3.fr>, 2021
//
// This software is governed by the CeCILL license under French law and
// abiding by the rules of distribution of free software.  You can  use,
// modify and/ or redistribute the software under the terms of the CeCILL
// license as circulated by CEA, CNRS and INRIA at the following URL
// "http://www.cecill.info".
//
// As a counterpart to the access to the source code and  rights to copy,
// modify and redistribute granted by the license, users are provided only
// with a limited warranty  and the software's author,  the holder of the
// economic rights,  and the successive licensors  have only  limited
// liability.
//
// In this respect, the user's attention is drawn to the risks associated
// with loading,  using,  modifying and/or developing or reproducing the
// software by the user in light of its specific status of free software,
// that may mean  that it is complicated to manipulate,  and  that  also
// therefore means  that it is reserved for developers  and  experienced
// professionals having in-depth computer knowledge. Users are therefore
// encouraged to load and test the software's suitability as regards their
// requirements in conditions enabling the security of their systems and/or
// data to be ensured and,  more generally, to use and operate it in the
// same conditions as regards security.
//
// The fact that you are presently reading this means that you have had
// knowledge of the CeCILL license and that you accept its terms.

package freeipa_test

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/ccin2p3/go-freeipa/freeipa"
)

func setup(t *testing.T) *freeipa.Client {
	tspt := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client, _, e := freeipa.Connect("dc1.test.local", tspt, "admin", "walrus123")
	if e != nil {
		t.Fatal(e)
	}
	return client
}

func noErr(t *testing.T, e error) {
	if e != nil {
		t.Fatalf("unexpected error: %v", e)
	}
}

func TestUser(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	client := setup(t)
	testNum := rand.Int()
	testUID := fmt.Sprintf("jdoe%v", testNum)

	find1Res, e := client.UserFind("", &freeipa.UserFindArgs{}, nil)
	noErr(t, e)
	find1Len := len(find1Res.Result)

	addRes, e := client.UserAdd(&freeipa.UserAddArgs{
		Givenname: "John",
		Sn:        "Doe",
	}, &freeipa.UserAddOptionalArgs{
		UID: freeipa.String(testUID),
	})
	noErr(t, e)
	if *addRes.Result.Givenname != "John" || addRes.Result.Sn != "Doe" {
		t.Errorf("unexpected names in: %v", addRes.Result)
	}

	find2Res, e := client.UserFind("", &freeipa.UserFindArgs{}, nil)
	noErr(t, e)
	if find1Len+1 != len(find2Res.Result) {
		t.Errorf("expected one new user, but got: %v and then %v", find1Res.Result, find2Res.Result)
	}
	var newUserF freeipa.User
	for _, u := range find2Res.Result {
		if u.UID == testUID {
			newUserF = u
		}
	}
	if !reflect.DeepEqual(newUserF.Givenname, freeipa.String("John")) || newUserF.Sn != "Doe" {
		t.Errorf("new user has wrong name: got %v %v, want John Doe", newUserF.Givenname, newUserF.Sn)
	}

	showRes, e := client.UserShow(&freeipa.UserShowArgs{}, &freeipa.UserShowOptionalArgs{
		UID:       freeipa.String(testUID),
		NoMembers: freeipa.Bool(true),
	})
	noErr(t, e)
	// these are only returned by Show, not Find
	newUserF.HasKeytab = freeipa.Bool(false)
	newUserF.HasPassword = freeipa.Bool(false)
	if !reflect.DeepEqual(newUserF, showRes.Result) {
		t.Errorf("expected user from Find and Show be equal: %v %v", &newUserF, &showRes.Result)
	}

	delRes, e := client.UserDel(&freeipa.UserDelArgs{}, &freeipa.UserDelOptionalArgs{
		UID: &[]string{testUID},
	})
	noErr(t, e)
	if !reflect.DeepEqual(delRes.Value, []string{testUID}) {
		t.Errorf("user not reported deleted, got: %v", delRes.Value)
	}

	find3Res, e := client.UserFind("", &freeipa.UserFindArgs{}, nil)
	noErr(t, e)
	if len(find3Res.Result) != find1Len {
		t.Errorf("expected the same users as at the start of the test, but initially got %v and now %v", find1Res.Result, find3Res.Result)
	}

	_, e = client.UserShow(&freeipa.UserShowArgs{}, &freeipa.UserShowOptionalArgs{
		UID:       freeipa.String(testUID),
		NoMembers: freeipa.Bool(true),
	})
	if e == nil {
		t.Errorf("showing user after deletion: got no error, but expected one")
	}
	ipaE, isIpaE := e.(*freeipa.Error)
	if !isIpaE {
		t.Errorf("got %v, but expected a freeipa error", e)
	}
	if ipaE.Code != freeipa.NotFoundCode {
		t.Errorf("got %v, but expected a NotFound error", ipaE)
	}
}
