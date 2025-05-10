package session

import (
	pb "StealthIMUser/StealthIM.Session"
	"StealthIMUser/config"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var conns []*grpc.ClientConn
var mainlock sync.RWMutex

func createConn(connID int) {
	log.Printf("[Session]Connect %d", connID+1)
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", config.LatestConfig.Session.Host, config.LatestConfig.Session.Port),
		grpc.WithTransportCredentials(
			insecure.NewCredentials()))
	if conn == nil {
		log.Printf("[Session]Connect %d Error %v\n", connID+1, err)
		conns[connID] = nil
		return
	}
	if err != nil {
		log.Printf("[Session]Connect %d Error %v\n", connID+1, err)
		conns[connID] = nil
		return
	}
	conns[connID] = conn
}

func checkAlive(connID int) {
	if len(conns) <= connID {
		return
	}
	for {
		if len(conns) <= connID {
			return
		}
		mainlock.Lock()
		if conns[connID] != nil {
			cli := pb.NewStealthIMSessionClient(conns[connID])
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err := cli.Ping(ctx, &pb.PingRequest{})
			cancel()
			if err == nil {
				mainlock.Unlock()
				continue
			}
		}
		createConn(connID)
		mainlock.Unlock()
		time.Sleep(5 * time.Second)
	}
}

// InitConns 扩缩容连接
func InitConns() {
	defer func() {
		mainlock.Lock()
		for _, conn := range conns {
			conn.Close()
		}
		mainlock.Unlock()
	}()
	log.Printf("[Session]Init Conns\n")
	for {
		time.Sleep(time.Second * 1)
		var lenTmp = len(conns)
		if lenTmp < config.LatestConfig.Session.ConnNum {
			log.Printf("[Session]Create Conn %d\n", lenTmp+1)
			mainlock.Lock()
			conns = append(conns, nil)
			mainlock.Unlock()
			go checkAlive(lenTmp)
		} else if lenTmp > config.LatestConfig.Session.ConnNum {
			log.Printf("[Session]Delete Conn %d\n", lenTmp)
			mainlock.Lock()
			conns[lenTmp-1].Close()
			conns = conns[:lenTmp-1]
			mainlock.Unlock()
		} else {
			time.Sleep(time.Second * 5)
		}
	}
}

// SetSession 写 Session
func SetSession(ctx context.Context, req *pb.SetRequest) (*pb.SetResponse, error) {
	breakFlag := true
	for breakFlag {
		select {
		case <-ctx.Done():
			// 上下文已取消或超时
			return nil, ctx.Err()
		default:
			// 尝试获取锁
			if mainlock.TryRLock() {
				breakFlag = false
				break
			}
			// 短暂休眠，避免CPU空转
			time.Sleep(time.Millisecond * 10)
		}
	}
	defer mainlock.RUnlock()
	conn, err := chooseConn()
	if err != nil {
		return nil, err
	}
	c := pb.NewStealthIMSessionClient(conn)
	res, err2 := c.Set(ctx, req)
	return res, err2
}

// 读取 Session 这里用不到便不在这里实现
