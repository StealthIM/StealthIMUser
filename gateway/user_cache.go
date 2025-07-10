package gateway

import (
	pbdb "StealthIMUser/StealthIM.DBGateway"
	pb "StealthIMUser/StealthIM.User"
	errorcode "StealthIMUser/errorcode"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// SetUserInfoCache Set user info cache
func SetUserInfoCache(rUserID int32, info *pb.UserInfoCache) error {
	key := fmt.Sprintf("%s%d", "user:info:", rUserID)

	// Serialize with protobuf
	data, err := proto.Marshal(info)
	if err != nil {
		return err
	}

	req := &pbdb.RedisSetBytesRequest{
		DBID:  0,
		Key:   key,
		Value: data,
		Ttl:   3600,
	}

	resp, err := ExecRedisBSet(req)
	if err != nil {
		return err
	}

	if resp.Result.Code != errorcode.Success {
		return fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	return nil
}

// GetUserInfoCache Get user info cache
func GetUserInfoCache(userID int32) (*pb.UserInfoCache, error) {
	key := fmt.Sprintf("%s%d", "user:info:", userID)

	req := &pbdb.RedisGetBytesRequest{
		DBID: 0,
		Key:  key,
	}

	resp, err := ExecRedisBGet(req)
	if err != nil {
		return nil, err
	}

	if resp.Result.Code != errorcode.Success {
		if resp.Result.Code == 404 {
			// Cache miss
			return nil, nil
		}
		return nil, fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	if len(resp.Value) == 0 {
		return nil, nil
	}

	var userInfo pb.UserInfoCache
	err = proto.Unmarshal(resp.Value, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// SetUserPublicCache Set user public info cache
func SetUserPublicCache(info *pb.UserPublicCache) error {
	key := fmt.Sprintf("%s%d:public", "user:info:", info.UserId)

	// Serialize with protobuf
	data, err := proto.Marshal(info)
	if err != nil {
		return err
	}

	req := &pbdb.RedisSetBytesRequest{
		DBID:  0,
		Key:   key,
		Value: data,
		Ttl:   3600,
	}

	resp, err := ExecRedisBSet(req)
	if err != nil {
		return err
	}

	if resp.Result.Code != errorcode.Success {
		return fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	return nil
}

// GetUserPublicCache Get user public info cache
func GetUserPublicCache(userID int32) (*pb.UserPublicCache, error) {
	key := fmt.Sprintf("%s%d:public", "user:info:", userID)

	req := &pbdb.RedisGetBytesRequest{
		DBID: 0,
		Key:  key,
	}

	resp, err := ExecRedisBGet(req)
	if err != nil {
		return nil, err
	}

	if resp.Result.Code != errorcode.Success {
		if resp.Result.Code == 404 {
			// Cache miss
			return nil, nil
		}
		return nil, fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	if len(resp.Value) == 0 {
		return nil, nil
	}

	var userInfo pb.UserPublicCache
	err = proto.Unmarshal(resp.Value, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// SetUserLoginCache Set user login info cache
func SetUserLoginCache(info *pb.UserLoginCache) error {
	key := fmt.Sprintf("%s%s", "user:auth:", info.Username)

	// Serialize with protobuf
	data, err := proto.Marshal(info)
	if err != nil {
		return err
	}

	req := &pbdb.RedisSetBytesRequest{
		DBID:  0,
		Key:   key,
		Value: data,
		Ttl:   3600,
	}

	resp, err := ExecRedisBSet(req)
	if err != nil {
		return err
	}

	if resp.Result.Code != errorcode.Success {
		return fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	return nil
}

// GetUserLoginCache Get user login info cache
func GetUserLoginCache(username string) (*pb.UserLoginCache, error) {
	key := fmt.Sprintf("%s%s", "user:auth:", username)

	req := &pbdb.RedisGetBytesRequest{
		DBID: 0,
		Key:  key,
	}

	resp, err := ExecRedisBGet(req)
	if err != nil {
		return nil, err
	}

	if resp.Result.Code != errorcode.Success {
		if resp.Result.Code == 404 {
			// Cache miss
			return nil, nil
		}
		return nil, fmt.Errorf("redis error: %s", resp.Result.Msg)
	}

	if len(resp.Value) == 0 {
		return nil, nil
	}

	var loginInfo pb.UserLoginCache
	err = proto.Unmarshal(resp.Value, &loginInfo)
	if err != nil {
		return nil, err
	}

	return &loginInfo, nil
}

// DeleteUserCache Delete user info cache
func DeleteUserCache(userID int32) error {
	// Delete full user info cache
	fullKey := fmt.Sprintf("%s%d", "user:info:", userID)
	fullReq := &pbdb.RedisDelRequest{
		DBID: 0,
		Key:  fullKey,
	}

	_, err := ExecRedisDel(fullReq)
	if err != nil {
		// Continue to delete other caches
	}

	// Delete user public info cache
	publicKey := fmt.Sprintf("%s%d:public", "user:info:", userID)
	publicReq := &pbdb.RedisDelRequest{
		DBID: 0,
		Key:  publicKey,
	}

	_, err = ExecRedisDel(publicReq)
	if err != nil {
		// Continue to delete other caches
	}

	return nil
}

// DeleteUserLoginCache Delete user login cache
func DeleteUserLoginCache(username string) error {
	key := fmt.Sprintf("%s%s", "user:auth:", username)
	req := &pbdb.RedisDelRequest{
		DBID: 0,
		Key:  key,
	}

	_, err := ExecRedisDel(req)
	if err != nil {
		return err
	}

	return nil
}
