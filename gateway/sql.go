package gateway

import (
	pb "StealthIMUser/StealthIM.DBGateway"
	"StealthIMUser/config"
	"context"
	"time"
)

// ExecSQL 运行 SQL 语句
func ExecSQL(sql *pb.SqlRequest) (*pb.SqlResponse, error) {
	mainlock.RLock()
	defer mainlock.RUnlock()
	conn, err := chooseConn()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.LatestConfig.DBGateway.Timeout)*time.Millisecond)
	defer cancel()
	c := pb.NewStealthIMDBGatewayClient(conn)
	res, err2 := c.Mysql(ctx, sql)
	return res, err2
}
