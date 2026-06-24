package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	CncListen   string `json:"cnc_listen"`
	AdminListen string `json:"admin_listen"`
	ScanListen  string `json:"scan_listen"`
	ProtoKey    string `json:"proto_key"`
	MysqlAddr   string `json:"mysql_addr"`
	MysqlUser   string `json:"mysql_user"`
	MysqlPass   string `json:"mysql_pass"`
	MysqlTable  string `json:"mysql_table"`
	HttpServer  string `json:"http_server"`
	TftpServer  string `json:"tftp_server"`
	BinPrefix   string `json:"bin_prefix"`
	BinPath     string `json:"bin_path"`
}

var cfg *Config

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.CncListen == "" {
		c.CncListen = "0.0.0.0:34129"
	}
	if c.AdminListen == "" {
		c.AdminListen = "0.0.0.0:34131"
	}
	if c.ScanListen == "" {
		c.ScanListen = "0.0.0.0:34130"
	}
	if c.MysqlAddr == "" {
		c.MysqlAddr = "127.0.0.1:3306"
	}
	if c.MysqlUser == "" {
		c.MysqlUser = "fnbnet"
	}
	if c.MysqlTable == "" {
		c.MysqlTable = "FemboyNetwork"
	}
	if c.HttpServer == "" {
		c.HttpServer = "193.23.220.76"
	}
	if c.TftpServer == "" {
		c.TftpServer = "193.23.220.76"
	}
	if c.BinPrefix == "" {
		c.BinPrefix = "fnbnet"
	}
	if c.BinPath == "" {
		c.BinPath = "/var/www/html/bins"
	}
	cfg = new(Config)
	*cfg = c
	return cfg, nil
}
