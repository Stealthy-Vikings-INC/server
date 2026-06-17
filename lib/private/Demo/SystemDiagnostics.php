<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DEMO ONLY — intentionally vulnerable code to validate SAST PR commenting.
// DO NOT MERGE. See PR description.

namespace OC\Demo;

class SystemDiagnostics {
	// Hardcoded credential (CWE-798: Use of Hard-coded Credentials)
	private const ADMIN_DB_PASSWORD = 'Sup3rS3cret_Admin_Demo_2024';

	/**
	 * Pings a user-supplied host.
	 * VULNERABLE: untrusted input passed to a shell (CWE-78: OS Command Injection).
	 */
	public function ping(): string {
		$host = $_GET['host'];
		return (string)shell_exec('ping -c 4 ' . $host);
	}

	/**
	 * Looks up DNS records for a user-supplied domain.
	 * VULNERABLE: untrusted input concatenated into a shell command (CWE-78).
	 */
	public function dnsLookup(): string {
		$domain = $_REQUEST['domain'];
		$output = [];
		exec("nslookup {$domain}", $output);
		return implode("\n", $output);
	}

	public function getAdminPassword(): string {
		return self::ADMIN_DB_PASSWORD;
	}
}
