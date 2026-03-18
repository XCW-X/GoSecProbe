package mysql

import (
	"database/sql"
	"time"
)

// SystemSettings 系统设置结构体
type SystemSettings struct {
	ID                  int64     `json:"id"`
	NetworkCard         string    `json:"network_card"`
	Concurrency         int       `json:"concurrency"`
	Timeout             int       `json:"timeout"`
	Retries             int       `json:"retries"`
	ProxyType           string    `json:"proxy_type"`
	ProxyURL            string    `json:"proxy_url"`
	ReverseDnslogDomain string    `json:"reverse_dnslog_domain"`
	ReverseDnslogAPI    string    `json:"reverse_dnslog_api"`
	ReverseRMIServer    string    `json:"reverse_rmi_server"`
	ReverseLDAPServer   string    `json:"reverse_ldap_server"`
	ReverseHTTPServer   string    `json:"reverse_http_server"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// GetSettings 获取系统设置
func GetSettings() (*SystemSettings, error) {
	settings := &SystemSettings{}

	query := `
	SELECT id, network_card, concurrency, timeout, retries,
	       proxy_type, proxy_url,
	       reverse_dnslog_domain, reverse_dnslog_api,
	       reverse_rmi_server, reverse_ldap_server, reverse_http_server,
	       created_at, updated_at
	FROM system_settings LIMIT 1`

	err := DB.QueryRow(query).Scan(
		&settings.ID, &settings.NetworkCard, &settings.Concurrency, &settings.Timeout, &settings.Retries,
		&settings.ProxyType, &settings.ProxyURL,
		&settings.ReverseDnslogDomain, &settings.ReverseDnslogAPI,
		&settings.ReverseRMIServer, &settings.ReverseLDAPServer, &settings.ReverseHTTPServer,
		&settings.CreatedAt, &settings.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return getDefaultSettings(), nil
	}
	if err != nil {
		return nil, err
	}

	return settings, nil
}

// UpdateSettings 更新系统设置
func UpdateSettings(settings *SystemSettings) error {
	query := `
	UPDATE system_settings SET
		network_card = ?,
		concurrency = ?,
		timeout = ?,
		retries = ?,
		proxy_type = ?,
		proxy_url = ?,
		reverse_dnslog_domain = ?,
		reverse_dnslog_api = ?,
		reverse_rmi_server = ?,
		reverse_ldap_server = ?,
		reverse_http_server = ?,
		updated_at = NOW()
	WHERE id = 1`

	_, err := DB.Exec(query,
		settings.NetworkCard,
		settings.Concurrency,
		settings.Timeout,
		settings.Retries,
		settings.ProxyType,
		settings.ProxyURL,
		settings.ReverseDnslogDomain,
		settings.ReverseDnslogAPI,
		settings.ReverseRMIServer,
		settings.ReverseLDAPServer,
		settings.ReverseHTTPServer,
	)
	return err
}

// getDefaultSettings 返回默认设置
func getDefaultSettings() *SystemSettings {
	return &SystemSettings{
		ID:                  1,
		NetworkCard:         "",
		Concurrency:         10,
		Timeout:             10,
		Retries:             2,
		ProxyType:           "",
		ProxyURL:            "",
		ReverseDnslogDomain: "",
		ReverseDnslogAPI:    "",
		ReverseRMIServer:    "",
		ReverseLDAPServer:   "",
		ReverseHTTPServer:   "",
	}
}
