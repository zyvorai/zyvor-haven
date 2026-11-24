// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

// SetSCIMLimits lowers the SCIM rate limits for a test and returns the restore func.
func SetSCIMLimits(req, fail int) func() {
	r, f := scimReqMax, scimFailMax
	scimReqMax, scimFailMax = req, fail
	return func() { scimReqMax, scimFailMax = r, f }
}

// SetSCIMScanCap lowers the list scan cap for a test and returns the restore func.
func SetSCIMScanCap(n int) func() {
	o := scimScanCap
	scimScanCap = n
	return func() { scimScanCap = o }
}
