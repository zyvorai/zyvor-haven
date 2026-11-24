// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//go:build ignore

// gen_common writes common.txt: a deterministic, PATTERN-DERIVED list of weak
// passwords (keyboard walks, years, seasons+year, first names+digits, famous
// words+suffixes). It is NOT a breach corpus.
//
// Regenerate: go run gen_common.go > common.txt
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func main() {
	set := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(s)
		if len(s) >= 4 && len(s) <= 40 {
			set[s] = true
		}
	}
	words := strings.Fields(`password passw0rd pass passwd secret letmein welcome admin administrator root login master
	qwerty qwertyuiop asdfgh asdfghjkl zxcvbn zxcvbnm azerty abc abcd abcde abcdef iloveyou love loveme lover
	monkey dragon football baseball basketball soccer hockey tennis golf shadow sunshine princess superman batman
	spiderman starwars pokemon naruto hello hunter killer trustno1 whatever freedom michael jordan harley ranger
	buster thomas tigger robert charlie matrix cheese coffee summer winter spring autumn flower purple orange
	yellow silver golden diamond ginger cookie pepper banana apple google facebook twitter youtube netflix amazon
	samsung iphone android windows linux ubuntu server system test testing guest user demo default changeme change
	computer internet network access mustang corvette ferrari porsche mercedes toyota honda yamaha camaro bailey
	maggie hannah jessica jennifer ashley nicole daniel andrew joshua matthew anthony william james john david
	richard joseph charles chris tiffany heather amanda brandon austin dallas texas london paris tokyo mumbai
	delhi india canada america england cricket tiger lion eagle phoenix falcon wolf bear panda rabbit butterfly
	rainbow thunder lightning storm hurricane ocean river mountain forest music guitar piano drums rock metal
	money dollar bitcoin crypto lucky happy smile angel devil heaven jesus allah krishna ganesh
	company office business manager sales support service backup database oracle mysql postgres redis mongo
	docker kubernetes jenkins gitlab github keycloak haven zyvor`)
	suffixes := []string{"", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "01", "02", "07", "11", "12", "13", "21",
		"22", "23", "69", "77", "99", "00", "007", "100", "111", "123", "1234", "12345", "123456", "321", "420", "666",
		"777", "786", "999", "!", "!!", "?", "#", "@", "$", "*", "@123", "@1234", "#1", "!1", "!@#", "_1", "_123",
		"2000", "2010", "2015", "2020", "2021", "2022", "2023", "2024", "2025", "2026", "123!", "1!", "12!", "123@"}
	for _, w := range words {
		for _, s := range suffixes {
			add(w + s)
		}
		add(w + w)
	}
	// keyboard walks and runs
	rows := []string{"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "1qaz2wsx3edc", "qazwsxedcrfv", "1q2w3e4r5t6y", "q1w2e3r4t5y6", "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "0987654321", "abcdefghijklmnopqrstuvwxyz"}
	for _, r := range rows {
		for i := 0; i < len(r); i++ {
			for l := 4; l <= 12 && i+l <= len(r); l++ {
				add(r[i : i+l])
				add(r[i:i+l] + "1")
				add(r[i:i+l] + "!")
				add(r[i:i+l] + "123")
			}
		}
	}
	for _, r := range []string{"1qaz2wsx", "1qazxsw2", "qwer1234", "asdf1234", "zxcv1234", "qwe123", "asd123", "zxc123", "q1w2e3r4", "1q2w3e4r", "qweasd", "qweasdzxc", "asdzxc", "123qwe", "123qweasd", "123abc", "abc123", "a1b2c3", "1a2b3c", "aaaaaa", "111111", "000000", "121212", "112233", "123123", "654321", "666666", "696969", "123321", "159753", "147258369", "123456789", "1234567890", "12345678", "1234567", "123456", "12345"} {
		add(r)
	}
	// repeated digits
	for d := 0; d <= 9; d++ {
		for l := 4; l <= 12; l++ {
			add(strings.Repeat(strconv.Itoa(d), l))
		}
	}
	// every 4-digit number (PINs and years), with common prefixes
	for n := 0; n < 10000; n++ {
		s := fmt.Sprintf("%04d", n)
		add(s)
		add("pass" + s)
		add("password" + s)
		add("admin" + s)
	}
	// seasons, months and weekdays with years
	seas := strings.Fields("spring summer autumn fall winter january february march april may june july august september october november december monday tuesday wednesday thursday friday saturday sunday")
	for _, s := range seas {
		for y := 1970; y <= 2030; y++ {
			add(s + strconv.Itoa(y))
			add(s + strconv.Itoa(y)[2:])
			add(s + strconv.Itoa(y) + "!")
		}
	}
	// first names + digits/years
	names := strings.Fields(`aaron adam adrian alex alexander alice amy andrea andy angela anna anne arthur barbara ben benjamin beth betty bill bob brad brian bruce carl carol caroline cathy chloe christian christina claire daisy dan dave deborah dennis diana donna dylan edward elizabeth emily emma eric ethan eva frank gary george grace greg harry helen henry isaac jack jacob jake jane jason jeff jeremy jerry jim joe jonathan julia julie justin karen kate katie keith kelly ken kevin kim larry laura lauren linda lisa lucy luke maria mark martin mary max megan mia mike molly nancy natalie nathan neil nick noah olivia oscar pamela patrick paul peter philip rachel ralph rebecca rick ron rose ruby ryan sam samantha sandra sara sarah scott sean sophie stephen steve susan tom tim tony tyler victoria vincent walter wayne zoe rahul rohit amit priya pooja neha anil sanjay vijay ravi arjun rajesh suresh ramesh deepak sunil ankit mohammed ahmed ali fatima omar`)
	for _, n := range names {
		for _, s := range []string{"", "1", "12", "123", "1234", "12345", "01", "007", "69", "99", "!", "@123", "2020", "2021", "2022", "2023", "2024", "2025", "1990", "1995", "2000", "2001", "2002"} {
			add(n + s)
		}
		for y := 1960; y <= 2010; y++ {
			add(n + strconv.Itoa(y))
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	fmt.Fprintf(os.Stderr, "%d entries\n", len(out))
	os.Stdout.WriteString(strings.Join(out, "\n") + "\n")
}
