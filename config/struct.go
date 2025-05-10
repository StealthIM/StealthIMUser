package config

// Config 主配置
type Config struct {
	DBGateway DBGatewayConfig `toml:"dbgateway"`
	GRPCProxy GRPCProxyConfig `toml:"grpc"`
	Session   SessionConfig   `toml:"session"`
}

// GRPCProxyConfig grpc Server配置
type GRPCProxyConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
	Log  bool   `toml:"log"`
}

// DBGatewayConfig grpc DBGateway 配置
type DBGatewayConfig struct {
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	ConnNum int    `toml:"conn_num"`
	Timeout int    `toml:"sql_timeout"`
}

// SessionConfig grpc Session 配置
type SessionConfig struct {
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	ConnNum int    `toml:"conn_num"`
}
