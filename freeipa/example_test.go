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
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/ccin2p3/go-freeipa/freeipa"
)

func Example_addUser() {
	tspt := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // WARNING DO NOT USE THIS OPTION IN PRODUCTION
		},
	}
	c, _, e := freeipa.Connect("dc1.test.local", tspt, "admin", "walrus123")
	if e != nil {
		log.Fatal(e)
	}

	rand.Seed(time.Now().UTC().UnixNano())
	uid := fmt.Sprintf("jdoe%v", rand.Int())

	res, e := c.UserAdd(&freeipa.UserAddArgs{
		Givenname: "John",
		Sn:        "Doe",
	}, &freeipa.UserAddOptionalArgs{
		UID: freeipa.String(uid),
	})
	if e != nil {
		log.Fatal(e)
	}

	fmt.Printf("Added user %v", *res.Result.Cn)
	// Output: Added user John Doe
}

func Example_errorHandling() {
	tspt := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // WARNING DO NOT USE THIS OPTION IN PRODUCTION
		},
	}
	c, _, e := freeipa.Connect("dc1.test.local", tspt, "admin", "walrus123")
	if e != nil {
		log.Fatal(e)
	}

	_, e = c.UserShow(&freeipa.UserShowArgs{}, &freeipa.UserShowOptionalArgs{
		UID: freeipa.String("somemissinguid"),
	})
	if e == nil {
		fmt.Printf("No error")
	} else if ipaE, ok := e.(*freeipa.Error); ok {
		fmt.Printf("FreeIPA error %v: %v\n", ipaE.Code, ipaE.Message)
		if ipaE.Code == freeipa.NotFoundCode {
			fmt.Println("(matched expected error code)")
		}
	} else {
		fmt.Printf("Other error: %v", e)
	}

	// Output: FreeIPA error 4001: somemissinguid: user not found
	// (matched expected error code)
}

func Example_kerberosLogin() {

	krb5Principal := "host/cc.in2p3.fr"
	krb5Realm := "CC.IN2P3.FR"

	krb5KtFd, err := os.Open("/etc/krb5.keytab")
	if err != nil {
		log.Fatal(err)
	}
	defer krb5KtFd.Close()

	krb5Fd, err := os.Open("/etc/krb5.conf")
	if err != nil {
		log.Fatal(err)
	}
	defer krb5Fd.Close()

	krb5ConnectOption := &freeipa.KerberosConnectOptions{
		Krb5ConfigReader: krb5Fd,
		KeytabReader:     krb5KtFd,
		Username:         krb5Principal,
		Realm:            krb5Realm,
	}

	tspt := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	c, err := freeipa.ConnectWithKerberos("dc1.test.local", tspt, krb5ConnectOption)
	if err != nil {
		log.Fatal(err)
	}

	sizeLimit := 5
	res, err := c.UserFind("", &freeipa.UserFindArgs{}, &freeipa.UserFindOptionalArgs{
		Sizelimit: &sizeLimit,
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, user := range res.Result {
		fmt.Printf("User[%s] HOME=%s\n", user.UID, *user.Homedirectory)
	}
}
