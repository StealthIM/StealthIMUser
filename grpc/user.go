package grpc

import (
	pb "StealthIMUser/StealthIM.User"
	"StealthIMUser/config"
	"StealthIMUser/errorcode"
	"StealthIMUser/gateway"
	"StealthIMUser/session"
	sqlHelper "StealthIMUser/sql"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"regexp"
	"time"

	pbdb "StealthIMUser/StealthIM.DBGateway"
	pbsession "StealthIMUser/StealthIM.Session"
)

// 生成随机盐值
func generateSalt() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return time.Now().String()
	}
	return hex.EncodeToString(b)
}

// 密码哈希
func hashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(password + salt))
	return hex.EncodeToString(h.Sum(nil))
}

// isValidUsername 判断用户名是否只包含数字、字母和下划线
func isValidUsername(username string) bool {
	pattern := `^[a-zA-Z0-9_]+$`
	matched, err := regexp.MatchString(pattern, username)
	if err != nil {
		return false
	}
	return matched
}

// isValidPassword 判断密码是否合法
func isValidPassword(password string) bool {
	pattern := `^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+$`
	matched, err := regexp.MatchString(pattern, password)
	if err != nil {
		return false
	}
	return matched
}

// Register user
func (s *server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call Register")
	}
	// Parameter validation
	if req.Username == "" || req.Password == "" || req.Nickname == "" {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username, password, or nickname cannot be empty",
			},
		}, nil
	}

	if len(req.Username) < 3 || len(req.Username) > 20 {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username length must be between 3 and 20 characters",
			},
		}, nil
	}
	if !isValidUsername(req.Username) {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username can only contain numbers, letters, and underscores",
			},
		}, nil
	}
	if len(req.Password) < 6 || len(req.Password) > 20 {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password length must be between 6 and 20 characters",
			},
		}, nil
	}
	if !isValidPassword(req.Password) {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
			},
		}, nil
	}

	// 先尝试从缓存获取登录信息
	loginCache, _ := gateway.GetUserLoginCache(req.Username)

	if loginCache != nil {
		if loginCache.UserId >= 0 {
			return &pb.RegisterResponse{
				Result: &pb.Result{
					Code: errorcode.UserAlreadyExists,
					Msg:  "User already exists",
				},
			}, nil
		}
	} else {
		for {
			// 从数据库查询用户
			sqlReq := &pbdb.SqlRequest{
				Sql: sqlHelper.CheckUserSQL,
				Db:  pbdb.SqlDatabases_Users,
				Params: []*pbdb.InterFaceType{
					{Response: &pbdb.InterFaceType_Str{Str: req.Username}},
				},
			}

			resp, err := gateway.ExecSQL(sqlReq)
			if err != nil {
				break
			}

			// 检查SQL执行结果
			if resp.Result.Code != errorcode.Success {
				break
			}

			// 检查用户是否存在
			if len(resp.Data) == 0 {
				// 更新缓存
				userInfoCache := &pb.UserInfoCache{
					UserId: -1,
				}
				go gateway.SetUserInfoCache(userInfoCache.UserId, userInfoCache)
				break
			}

			// 获取用户数据
			userData := resp.Data[0].Result

			// 获取密码信息
			userID := userData[0].GetInt32()
			hashedPassword := userData[3].GetStr()
			salt := userData[4].GetStr()
			loginLevel := userData[5].GetInt32()

			// 更新登录缓存
			loginCache = &pb.UserLoginCache{
				UserId:     userID,
				Username:   req.Username,
				Password:   hashedPassword,
				Salt:       salt,
				LoginLevel: loginLevel,
			}

			go gateway.SetUserLoginCache(loginCache)

			if true {
				return &pb.RegisterResponse{
					Result: &pb.Result{
						Code: errorcode.UserAlreadyExists,
						Msg:  "User already exists",
					},
				}, nil
			}
		}
	}

	// 生成盐值和加密密码
	salt := generateSalt()
	hashedPassword := hashPassword(req.Password, salt)

	// 插入用户认证信息
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.InsertUserAuthSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: req.Username}},
			{Response: &pbdb.InterFaceType_Str{Str: req.Nickname}},
			{Response: &pbdb.InterFaceType_Str{Str: hashedPassword}},
			{Response: &pbdb.InterFaceType_Str{Str: salt}},
		},
		GetLastInsertId: true,
		Commit:          true,
	}

	// 执行SQL
	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.RegisterResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 获取用户ID
	userID := int32(resp.LastInsertId)

	// 插入用户信息
	infoReq := &pbdb.SqlRequest{
		Sql: sqlHelper.InsertUserInfoSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Int32{Int32: userID}},
			{Response: &pbdb.InterFaceType_Str{Str: req.Email}},
			{Response: &pbdb.InterFaceType_Str{Str: req.PhoneNumber}},
		},
		Commit: true,
	}

	gateway.ExecSQL(infoReq)

	// 返回结果
	return &pb.RegisterResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

// Login user
func (s *server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call Login")
	}
	// Parameter validation
	if req.Username == "" || req.Password == "" {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username or password cannot be empty",
			},
		}, nil
	}

	if len(req.Username) < 3 || len(req.Username) > 20 {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username length must be between 3 and 20 characters",
			},
		}, nil
	}
	if !isValidUsername(req.Username) {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username can only contain numbers, letters, and underscores",
			},
		}, nil
	}
	if len(req.Password) < 6 || len(req.Password) > 20 {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password length must be between 6 and 20 characters",
			},
		}, nil
	}
	if !isValidPassword(req.Password) {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
			},
		}, nil
	}

	var userID int32
	var hashedPassword, salt string
	var loginLevel int32

	// 先尝试从缓存获取登录信息
	loginCache, _ := gateway.GetUserLoginCache(req.Username)

	if loginCache != nil {
		if loginCache.UserId < 0 {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		// 使用缓存的登录信息
		userID = loginCache.UserId
		hashedPassword = loginCache.Password
		salt = loginCache.Salt
		loginLevel = loginCache.LoginLevel

		// 验证密码
		inputHash := hashPassword(req.Password, salt)
		if inputHash != hashedPassword {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserPasswordError,
					Msg:  "Incorrect password",
				},
			}, nil
		}

		// 检查用户状态
		if loginLevel != 0 {
			var msg string
			switch loginLevel {
			case 1:
				msg = "Account has been logged out"
			case 2:
				msg = "Account has been banned"
			default:
				msg = "Account status abnormal"
			}
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserPermissionDenied,
					Msg:  msg,
				},
			}, nil
		}
	} else {
		// 从数据库查询用户
		sqlReq := &pbdb.SqlRequest{
			Sql: sqlHelper.CheckUserSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Str{Str: req.Username}},
			},
		}

		resp, err := gateway.ExecSQL(sqlReq)
		if err != nil {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if resp.Result.Code != errorcode.Success {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  resp.Result.Msg,
				},
			}, nil
		}

		// 检查用户是否存在
		if len(resp.Data) == 0 {
			// 更新缓存
			userInfoCache := &pb.UserInfoCache{
				UserId: -1,
			}
			go gateway.SetUserInfoCache(userInfoCache.UserId, userInfoCache)
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist or has been disabled",
				},
			}, nil
		}

		// 获取用户数据
		userData := resp.Data[0].Result

		// 获取密码信息
		userID = userData[0].GetInt32()
		hashedPassword = userData[3].GetStr()
		salt = userData[4].GetStr()
		loginLevel = userData[5].GetInt32()

		// 更新登录缓存
		loginCache = &pb.UserLoginCache{
			UserId:     userID,
			Username:   req.Username,
			Password:   hashedPassword,
			Salt:       salt,
			LoginLevel: loginLevel,
		}

		go gateway.SetUserLoginCache(loginCache)

		// 验证密码
		inputHash := hashPassword(req.Password, salt)
		if inputHash != hashedPassword {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserPasswordError,
					Msg:  "Incorrect password",
				},
			}, nil
		}

		// 检查用户状态
		if loginLevel != 0 {
			var msg string
			switch loginLevel {
			case 1:
				msg = "Account has been logged out"
			case 2:
				msg = "Account has been banned"
			default:
				msg = "Account status abnormal"
			}
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserPermissionDenied,
					Msg:  msg,
				},
			}, nil
		}
	}
	getSessionRet := make(chan string, 1)
	go func() {
		getSessionRet <- (func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := session.SetSession(ctx, &pbsession.SetRequest{
				Uid: userID,
			})
			if err != nil {
				return ""
			}
			if resp.Result.Code != errorcode.Success {
				return ""
			}
			return resp.Session
		}())
	}()

	// 获取用户详细信息
	var userInfo *pb.UserInfo

	// 先尝试从缓存获取用户信息
	userInfoCache, _ := gateway.GetUserInfoCache(userID)

	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist or has been disabled",
				},
			}, nil
		}
		// 将缓存数据转换为UserInfo
		userInfo = &pb.UserInfo{
			Username:    userInfoCache.Username,
			Nickname:    userInfoCache.Nickname,
			LoginLevel:  userInfoCache.LoginLevel,
			Email:       userInfoCache.Email,
			PhoneNumber: userInfoCache.PhoneNumber,
			CreateTime:  userInfoCache.CreateTime,
			Vip:         userInfoCache.Vip,
		}
	} else {
		// 从数据库获取用户信息
		infoReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: userID}},
			},
		}

		infoResp, err := gateway.ExecSQL(infoReq)
		if err != nil {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if infoResp.Result.Code != errorcode.Success || len(infoResp.Data) == 0 {
			return &pb.LoginResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 获取用户信息
		infoData := infoResp.Data[0].Result

		// 构建用户信息
		userid := infoData[0].GetInt32()
		userInfo = &pb.UserInfo{
			Username:    infoData[1].GetStr(),
			Nickname:    infoData[2].GetStr(),
			LoginLevel:  infoData[3].GetInt32(),
			Email:       infoData[4].GetStr(),
			PhoneNumber: infoData[5].GetStr(),
			CreateTime:  infoData[6].GetStr(),
			Vip:         infoData[7].GetInt32(),
		}

		// 更新缓存
		userInfoCache = &pb.UserInfoCache{
			Username:    userInfo.Username,
			Nickname:    userInfo.Nickname,
			LoginLevel:  userInfo.LoginLevel,
			Email:       userInfo.Email,
			PhoneNumber: userInfo.PhoneNumber,
			CreateTime:  userInfo.CreateTime,
			Vip:         userInfo.Vip,
		}

		go gateway.SetUserInfoCache(userid, userInfoCache)
	}

	session := <-getSessionRet
	if session == "" {
		return &pb.LoginResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Session Internal error",
			},
		}, nil
	}

	// 返回结果
	return &pb.LoginResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
		Session:  session,
		UserInfo: userInfo,
	}, nil
}

// Logout user
func (s *server) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call Logout")
	}
	// Parameter validation
	if req.UserId < 0 {
		return &pb.LogoutResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Invalid user ID",
			},
		}, nil
	}

	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)

	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.LogoutResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	} else {
		for {
			// 从数据库获取用户信息
			infoReq := &pbdb.SqlRequest{
				Sql: sqlHelper.GetUserInfoSQL,
				Db:  pbdb.SqlDatabases_Users,
				Params: []*pbdb.InterFaceType{
					{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
				},
			}

			infoResp, err := gateway.ExecSQL(infoReq)
			if err != nil {
				break
			}

			// 检查SQL执行结果
			if infoResp.Result.Code != errorcode.Success || len(infoResp.Data) == 0 {
				go gateway.SetUserInfoCache(req.UserId, &pb.UserInfoCache{
					UserId: -1,
				})
				return &pb.LogoutResponse{
					Result: &pb.Result{
						Code: errorcode.UserNotFound,
						Msg:  "User does not exist",
					},
				}, nil
			}

			// 获取用户信息
			infoData := infoResp.Data[0].Result

			// 构建用户信息
			userid := infoData[0].GetInt32()
			userInfo := &pb.UserInfo{
				Username:    infoData[1].GetStr(),
				Nickname:    infoData[2].GetStr(),
				LoginLevel:  infoData[3].GetInt32(),
				Email:       infoData[4].GetStr(),
				PhoneNumber: infoData[5].GetStr(),
				CreateTime:  infoData[6].GetStr(),
				Vip:         infoData[7].GetInt32(),
			}

			// 更新缓存
			userInfoCache = &pb.UserInfoCache{
				Username:    userInfo.Username,
				Nickname:    userInfo.Nickname,
				LoginLevel:  userInfo.LoginLevel,
				Email:       userInfo.Email,
				PhoneNumber: userInfo.PhoneNumber,
				CreateTime:  userInfo.CreateTime,
				Vip:         userInfo.Vip,
			}

			go gateway.SetUserInfoCache(userid, userInfoCache)

			if true {
				break
			}
		}
	}

	// 更新用户状态为注销
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.UpdateUserStatusSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Int32{Int32: 1}},
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
		GetRowCount: true,
		Commit:      true,
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.LogoutResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.LogoutResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查是否更新成功
	if resp.RowsAffected == 0 {
		return &pb.LogoutResponse{
			Result: &pb.Result{
				Code: errorcode.UserNotFound,
				Msg:  "User does not exist",
			},
		}, nil
	}

	// 清除缓存
	go func() {
		err := gateway.DeleteUserCache(req.UserId)
		// 查询用户名
		nameReq := &pbdb.SqlRequest{
			Sql: "SELECT username FROM user_auth WHERE uid = ?",
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
			Commit: true,
		}

		nameResp, err := gateway.ExecSQL(nameReq)
		if err == nil && nameResp.Result.Code == errorcode.Success && len(nameResp.Data) > 0 {
			username := nameResp.Data[0].Result[0].GetStr()
			if username != "" {
				err = gateway.DeleteUserLoginCache(username)
			}
		}
	}()

	// 返回结果
	return &pb.LogoutResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

// GetUserInfo get user's own information
func (s *server) GetUserInfo(ctx context.Context, req *pb.GetUserInfoRequest) (*pb.GetUserInfoResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call GetUserInfo")
	}
	// Parameter validation
	if req.UserId <= 0 {
		return &pb.GetUserInfoResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "UserID not found",
			},
		}, nil
	}

	var userInfo *pb.UserInfo

	// 先尝试从缓存获取用户信息
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)

	if userInfoCache != nil {
		// 使用缓存数据
		if userInfoCache.UserId == -1 {
			return &pb.GetUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		userInfo = &pb.UserInfo{
			Username:    userInfoCache.Username,
			Nickname:    userInfoCache.Nickname,
			LoginLevel:  userInfoCache.LoginLevel,
			Email:       userInfoCache.Email,
			PhoneNumber: userInfoCache.PhoneNumber,
			CreateTime:  userInfoCache.CreateTime,
			Vip:         userInfoCache.Vip,
		}
	} else {
		// 查询用户信息
		sqlReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
		}

		resp, err := gateway.ExecSQL(sqlReq)
		if err != nil {
			return &pb.GetUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if resp.Result.Code != errorcode.Success {
			return &pb.GetUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  resp.Result.Msg,
				},
			}, nil
		}

		// 检查用户是否存在
		if len(resp.Data) == 0 {
			return &pb.GetUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User not found",
				},
			}, nil
		}

		// 获取用户信息
		userData := resp.Data[0].Result

		// 构建用户信息
		userid := userData[0].GetInt32()
		userInfo = &pb.UserInfo{
			Username:    userData[1].GetStr(),
			Nickname:    userData[2].GetStr(),
			LoginLevel:  userData[3].GetInt32(),
			Email:       userData[4].GetStr(),
			PhoneNumber: userData[5].GetStr(),
			CreateTime:  userData[6].GetStr(),
			Vip:         userData[7].GetInt32(),
		}

		// 写入缓存
		userInfoCache = &pb.UserInfoCache{
			Username:    userInfo.Username,
			Nickname:    userInfo.Nickname,
			LoginLevel:  userInfo.LoginLevel,
			Email:       userInfo.Email,
			PhoneNumber: userInfo.PhoneNumber,
			CreateTime:  userInfo.CreateTime,
			Vip:         userInfo.Vip,
		}

		go gateway.SetUserInfoCache(userid, userInfoCache)
	}

	// 返回结果
	return &pb.GetUserInfoResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
		UserInfo: userInfo,
	}, nil
}

// GetOtherUserInfo get other user's information
func (s *server) GetOtherUserInfo(ctx context.Context, req *pb.GetOtherUserInfoRequest) (*pb.GetOtherUserInfoResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call GetOtherUserInfo")
	}
	if req.Username == "" {
		return &pb.GetOtherUserInfoResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username cannot be empty",
			},
		}, nil
	}

	if len(req.Username) < 3 || len(req.Username) > 20 {
		return &pb.GetOtherUserInfoResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username length must be between 3 and 20 characters",
			},
		}, nil
	}
	if !isValidUsername(req.Username) {
		return &pb.GetOtherUserInfoResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Username can only contain numbers, letters, and underscores",
			},
		}, nil
	}

	var userID int32
	var hashedPassword, salt string
	var loginLevel int32

	// 先尝试从缓存获取登录信息
	loginCache, _ := gateway.GetUserLoginCache(req.Username)

	if loginCache != nil {
		if loginCache.UserId < 0 {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		// 使用缓存的登录信息
		userID = loginCache.UserId
		hashedPassword = loginCache.Password
		salt = loginCache.Salt
		loginLevel = loginCache.LoginLevel

		// 检查用户状态
		if loginLevel != 0 {
			var msg string
			switch loginLevel {
			case 1:
				msg = "Account has been logged out"
			case 2:
				msg = "Account has been banned"
			default:
				msg = "Account status abnormal"
			}
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserPermissionDenied,
					Msg:  msg,
				},
			}, nil
		}
	} else {
		// 从数据库查询用户
		sqlReq := &pbdb.SqlRequest{
			Sql: sqlHelper.CheckUserSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Str{Str: req.Username}},
			},
		}

		resp, err := gateway.ExecSQL(sqlReq)
		if err != nil {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if resp.Result.Code != errorcode.Success {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  resp.Result.Msg,
				},
			}, nil
		}

		// 检查用户是否存在
		if len(resp.Data) == 0 {
			// 更新缓存
			userInfoCache := &pb.UserInfoCache{
				UserId: -1,
			}
			go gateway.SetUserInfoCache(userInfoCache.UserId, userInfoCache)
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist or has been disabled",
				},
			}, nil
		}

		// 获取用户数据
		userData := resp.Data[0].Result

		// 获取密码信息
		userID = userData[0].GetInt32()
		hashedPassword = userData[3].GetStr()
		salt = userData[4].GetStr()
		loginLevel = userData[5].GetInt32()

		// 更新登录缓存
		loginCache = &pb.UserLoginCache{
			UserId:     userID,
			Username:   req.Username,
			Password:   hashedPassword,
			Salt:       salt,
			LoginLevel: loginLevel,
		}

		go gateway.SetUserLoginCache(loginCache)

		// 检查用户状态
		if loginLevel != 0 {
			var msg string
			switch loginLevel {
			case 1:
				msg = "Account has been logged out"
			case 2:
				msg = "Account has been banned"
			default:
				msg = "Account status abnormal"
			}
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserPermissionDenied,
					Msg:  msg,
				},
			}, nil
		}
	}

	var userInfo *pb.PublicUserInfo

	// 先尝试从缓存获取用户信息
	userPublicCache, _ := gateway.GetUserInfoCache(userID)

	if userPublicCache != nil {
		if userPublicCache.UserId == -1 {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist or has been disabled",
				},
			}, nil
		}
		// 使用缓存数据
		userInfo = &pb.PublicUserInfo{
			Nickname: userPublicCache.Nickname,
			Vip:      userPublicCache.Vip,
		}
	} else {
		// 查询用户信息
		sqlReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: userID}},
			},
		}

		resp, err := gateway.ExecSQL(sqlReq)
		if err != nil {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if resp.Result.Code != errorcode.Success {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  resp.Result.Msg,
				},
			}, nil
		}

		// 检查用户是否存在
		if len(resp.Data) == 0 {
			return &pb.GetOtherUserInfoResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist or has been disabled",
				},
			}, nil
		}

		// 获取用户信息
		userData := resp.Data[0].Result

		// 构建用户信息
		userInfo = &pb.PublicUserInfo{
			Nickname: userData[1].GetStr(),
			Vip:      userData[2].GetInt32(),
		}
		userid := userData[0].GetInt32()
		fullUserInfo := &pb.UserInfo{
			Username:    userData[1].GetStr(),
			Nickname:    userData[2].GetStr(),
			LoginLevel:  userData[3].GetInt32(),
			Email:       userData[4].GetStr(),
			PhoneNumber: userData[5].GetStr(),
			CreateTime:  userData[6].GetStr(),
			Vip:         userData[7].GetInt32(),
		}
		userInfoCache := &pb.UserInfoCache{
			Username:    fullUserInfo.Username,
			Nickname:    fullUserInfo.Nickname,
			LoginLevel:  fullUserInfo.LoginLevel,
			Email:       fullUserInfo.Email,
			PhoneNumber: fullUserInfo.PhoneNumber,
			CreateTime:  fullUserInfo.CreateTime,
			Vip:         fullUserInfo.Vip,
		}

		go gateway.SetUserInfoCache(userid, userInfoCache)
	}

	// 返回结果
	return &pb.GetOtherUserInfoResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
		UserInfo: userInfo,
	}, nil
}

// 修改用户密码
func (s *server) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call ChangePassword")
	}

	// 参数验证
	if req.UserId <= 0 {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Invalid user ID",
			},
		}, nil
	}

	if req.NewPassword == "" {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password cannot be empty",
			},
		}, nil
	}

	if len(req.NewPassword) < 6 || len(req.NewPassword) > 20 {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password length must be between 6 and 20 characters",
			},
		}, nil
	}

	if !isValidPassword(req.NewPassword) {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
			},
		}, nil
	}

	// 验证用户是否存在
	username := ""
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)
	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.ChangePasswordResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		username = userInfoCache.Username
	} else {
		// 从数据库获取用户信息
		infoReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
		}

		resp, err := gateway.ExecSQL(infoReq)
		if err != nil {
			return &pb.ChangePasswordResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if resp.Result.Code != errorcode.Success || len(resp.Data) == 0 {
			go gateway.SetUserInfoCache(req.UserId, &pb.UserInfoCache{
				UserId: -1,
			})
			return &pb.ChangePasswordResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}

		// 获取用户信息
		userData := resp.Data[0].Result

		// 构建用户信息
		userid := userData[0].GetInt32()
		fullUserInfo := &pb.UserInfo{
			Username:    userData[1].GetStr(),
			Nickname:    userData[2].GetStr(),
			LoginLevel:  userData[3].GetInt32(),
			Email:       userData[4].GetStr(),
			PhoneNumber: userData[5].GetStr(),
			CreateTime:  userData[6].GetStr(),
			Vip:         userData[7].GetInt32(),
		}
		userInfoCache := &pb.UserInfoCache{
			Username:    fullUserInfo.Username,
			Nickname:    fullUserInfo.Nickname,
			LoginLevel:  fullUserInfo.LoginLevel,
			Email:       fullUserInfo.Email,
			PhoneNumber: fullUserInfo.PhoneNumber,
			CreateTime:  fullUserInfo.CreateTime,
			Vip:         fullUserInfo.Vip,
		}
		username = fullUserInfo.Username

		go gateway.SetUserInfoCache(userid, userInfoCache)

	}

	// 生成新的盐值和加密密码
	salt := generateSalt()
	hashedPassword := hashPassword(req.NewPassword, salt)

	// 更新密码
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.UpdateUserPasswordSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: hashedPassword}},
			{Response: &pbdb.InterFaceType_Str{Str: salt}},
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
		GetRowCount: true,
		Commit:      true,
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: 6,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查是否更新成功
	if resp.RowsAffected == 0 {
		return &pb.ChangePasswordResponse{
			Result: &pb.Result{
				Code: errorcode.UserInternalError,
				Msg:  "Failed to update password",
			},
		}, nil
	}

	// 清除缓存
	go gateway.DeleteUserLoginCache(username)

	// 返回结果
	return &pb.ChangePasswordResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

// 修改用户昵称
func (s *server) ChangeNickname(ctx context.Context, req *pb.ChangeNicknameRequest) (*pb.ChangeNicknameResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call ChangeNickname")
	}

	// 参数验证
	if req.UserId <= 0 {
		return &pb.ChangeNicknameResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Invalid user ID",
			},
		}, nil
	}

	if req.NewNickname == "" {
		return &pb.ChangeNicknameResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Nickname cannot be empty",
			},
		}, nil
	}

	// 验证用户是否存在
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)
	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.ChangeNicknameResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	} else {
		// 从数据库获取用户信息
		infoReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
		}

		infoResp, err := gateway.ExecSQL(infoReq)
		if err != nil {
			return &pb.ChangeNicknameResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if infoResp.Result.Code != errorcode.Success || len(infoResp.Data) == 0 {
			go gateway.SetUserInfoCache(req.UserId, &pb.UserInfoCache{
				UserId: -1,
			})
			return &pb.ChangeNicknameResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	}

	// 更新昵称
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.UpdateUserNicknameSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: req.NewNickname}},
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
		GetRowCount: true,
		Commit:      true,
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.ChangeNicknameResponse{
			Result: &pb.Result{
				Code: 4,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.ChangeNicknameResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查是否更新成功
	if resp.RowsAffected == 0 {
		return &pb.ChangeNicknameResponse{
			Result: &pb.Result{
				Code: errorcode.UserInternalError,
				Msg:  "Failed to update nickname",
			},
		}, nil
	}

	// 清除缓存
	go gateway.DeleteUserCache(req.UserId)

	// 返回结果
	return &pb.ChangeNicknameResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

// 修改用户邮箱
func (s *server) ChangeEmail(ctx context.Context, req *pb.ChangeEmailRequest) (*pb.ChangeEmailResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call ChangeEmail")
	}

	// 参数验证
	if req.UserId <= 0 {
		return &pb.ChangeEmailResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Invalid user ID",
			},
		}, nil
	}

	// 验证邮箱格式 (这里只是简单验证，实际可能需要更复杂的验证)
	if req.NewEmail != "" {
		emailPattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(emailPattern, req.NewEmail)
		if err != nil || !matched {
			return &pb.ChangeEmailResponse{
				Result: &pb.Result{
					Code: errorcode.UserInvalidParameter,
					Msg:  "Invalid email format",
				},
			}, nil
		}
	}

	// 验证用户是否存在
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)
	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.ChangeEmailResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	} else {
		// 从数据库获取用户信息
		infoReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
		}

		infoResp, err := gateway.ExecSQL(infoReq)
		if err != nil {
			return &pb.ChangeEmailResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if infoResp.Result.Code != errorcode.Success || len(infoResp.Data) == 0 {
			go gateway.SetUserInfoCache(req.UserId, &pb.UserInfoCache{
				UserId: -1,
			})
			return &pb.ChangeEmailResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	}

	// 更新邮箱
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.UpdateUserEmailSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: req.NewEmail}},
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
		GetRowCount: true,
		Commit:      true,
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.ChangeEmailResponse{
			Result: &pb.Result{
				Code: 4,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.ChangeEmailResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查是否更新成功
	if resp.RowsAffected == 0 {
		return &pb.ChangeEmailResponse{
			Result: &pb.Result{
				Code: errorcode.UserInternalError,
				Msg:  "Failed to update email",
			},
		}, nil
	}

	// 清除缓存
	go gateway.DeleteUserCache(req.UserId)

	// 返回结果
	return &pb.ChangeEmailResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

// 修改用户电话号码
func (s *server) ChangePhoneNumber(ctx context.Context, req *pb.ChangePhoneNumberRequest) (*pb.ChangePhoneNumberResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call ChangePhoneNumber")
	}

	// 参数验证
	if req.UserId <= 0 {
		return &pb.ChangePhoneNumberResponse{
			Result: &pb.Result{
				Code: errorcode.UserInvalidParameter,
				Msg:  "Invalid user ID",
			},
		}, nil
	}

	// 验证电话号码格式 (这里只是简单验证，实际可能需要更复杂的验证)
	if req.NewPhoneNumber != "" {
		phonePattern := `^\+?[0-9]{6,15}$`
		matched, err := regexp.MatchString(phonePattern, req.NewPhoneNumber)
		if err != nil || !matched {
			return &pb.ChangePhoneNumberResponse{
				Result: &pb.Result{
					Code: errorcode.UserInvalidParameter,
					Msg:  "Invalid phone number format",
				},
			}, nil
		}
	}

	// 验证用户是否存在
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)
	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.ChangePhoneNumberResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	} else {
		// 从数据库获取用户信息
		infoReq := &pbdb.SqlRequest{
			Sql: sqlHelper.GetUserInfoSQL,
			Db:  pbdb.SqlDatabases_Users,
			Params: []*pbdb.InterFaceType{
				{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
			},
		}

		infoResp, err := gateway.ExecSQL(infoReq)
		if err != nil {
			return &pb.ChangePhoneNumberResponse{
				Result: &pb.Result{
					Code: errorcode.ServerInternalComponentError,
					Msg:  "Internal error",
				},
			}, nil
		}

		// 检查SQL执行结果
		if infoResp.Result.Code != errorcode.Success || len(infoResp.Data) == 0 {
			go gateway.SetUserInfoCache(req.UserId, &pb.UserInfoCache{
				UserId: -1,
			})
			return &pb.ChangePhoneNumberResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
	}

	// 更新电话号码
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.UpdateUserPhoneNumberSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: req.NewPhoneNumber}},
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
		GetRowCount: true,
		Commit:      true,
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.ChangePhoneNumberResponse{
			Result: &pb.Result{
				Code: 4,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.ChangePhoneNumberResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查是否更新成功
	if resp.RowsAffected == 0 {
		return &pb.ChangePhoneNumberResponse{
			Result: &pb.Result{
				Code: errorcode.UserInternalError,
				Msg:  "Failed to update phone number",
			},
		}, nil
	}

	// 清除缓存
	go gateway.DeleteUserCache(req.UserId)

	// 返回结果
	return &pb.ChangePhoneNumberResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
	}, nil
}

func (s *server) GetUsernameByUID(ctx context.Context, req *pb.GetUsernameByUIDRequest) (*pb.GetUsernameByUIDResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call GetUsernameByUIDRequest")
	}

	// 检查用户是否存在
	userInfoCache, _ := gateway.GetUserInfoCache(req.UserId)
	if userInfoCache != nil {
		if userInfoCache.UserId == -1 {
			return &pb.GetUsernameByUIDResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		return &pb.GetUsernameByUIDResponse{
			Result: &pb.Result{
				Code: errorcode.Success,
				Msg:  "",
			},
			Username: userInfoCache.Username,
		}, nil
	}
	// 查询用户信息
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.GetUserInfoSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Int32{Int32: req.UserId}},
		},
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.GetUsernameByUIDResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.GetUsernameByUIDResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查用户是否存在
	if len(resp.Data) == 0 {
		return &pb.GetUsernameByUIDResponse{
			Result: &pb.Result{
				Code: errorcode.UserNotFound,
				Msg:  "User does not exist",
			},
		}, nil
	}

	// 获取用户信息
	userData := resp.Data[0].Result

	// 构建用户信息
	userid := userData[0].GetInt32()
	userInfo := &pb.UserInfo{
		Username:    userData[1].GetStr(),
		Nickname:    userData[2].GetStr(),
		LoginLevel:  userData[3].GetInt32(),
		Email:       userData[4].GetStr(),
		PhoneNumber: userData[5].GetStr(),
		CreateTime:  userData[6].GetStr(),
		Vip:         userData[7].GetInt32(),
	}

	// 写入缓存
	userInfoCache = &pb.UserInfoCache{
		Username:    userInfo.Username,
		Nickname:    userInfo.Nickname,
		LoginLevel:  userInfo.LoginLevel,
		Email:       userInfo.Email,
		PhoneNumber: userInfo.PhoneNumber,
		CreateTime:  userInfo.CreateTime,
		Vip:         userInfo.Vip,
	}

	go gateway.SetUserInfoCache(userid, userInfoCache)
	return &pb.GetUsernameByUIDResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
		Username: userInfo.Username,
	}, nil
}

func (s *server) GetUIDByUsername(ctx context.Context, req *pb.GetUIDByUsernameRequest) (*pb.GetUIDByUsernameResponse, error) {
	if config.LatestConfig.GRPCProxy.Log {
		log.Println("[GRPC] Call GetUIDByUsernameRequest")
	}

	// 先尝试从缓存获取登录信息
	loginCache, _ := gateway.GetUserLoginCache(req.Username)

	if loginCache != nil {
		if loginCache.UserId < 0 {
			return &pb.GetUIDByUsernameResponse{
				Result: &pb.Result{
					Code: errorcode.UserNotFound,
					Msg:  "User does not exist",
				},
			}, nil
		}
		// 使用缓存的登录信息
		userID := loginCache.UserId
		return &pb.GetUIDByUsernameResponse{
			Result: &pb.Result{
				Code: errorcode.Success,
				Msg:  "",
			},
			UserId: userID,
		}, nil
	}
	// 从数据库查询用户
	sqlReq := &pbdb.SqlRequest{
		Sql: sqlHelper.CheckUserSQL,
		Db:  pbdb.SqlDatabases_Users,
		Params: []*pbdb.InterFaceType{
			{Response: &pbdb.InterFaceType_Str{Str: req.Username}},
		},
	}

	resp, err := gateway.ExecSQL(sqlReq)
	if err != nil {
		return &pb.GetUIDByUsernameResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  "Internal error",
			},
		}, nil
	}

	// 检查SQL执行结果
	if resp.Result.Code != errorcode.Success {
		return &pb.GetUIDByUsernameResponse{
			Result: &pb.Result{
				Code: errorcode.ServerInternalComponentError,
				Msg:  resp.Result.Msg,
			},
		}, nil
	}

	// 检查用户是否存在
	if len(resp.Data) == 0 {
		// 更新缓存
		userInfoCache := &pb.UserInfoCache{
			UserId: -1,
		}
		go gateway.SetUserInfoCache(userInfoCache.UserId, userInfoCache)
		return &pb.GetUIDByUsernameResponse{
			Result: &pb.Result{
				Code: errorcode.UserNotFound,
				Msg:  "User does not exist or has been disabled",
			},
		}, nil
	}

	// 获取用户数据
	userData := resp.Data[0].Result

	// 获取密码信息
	userID := userData[0].GetInt32()
	hashedPassword := userData[3].GetStr()
	salt := userData[4].GetStr()
	loginLevel := userData[5].GetInt32()

	// 更新登录缓存
	loginCache = &pb.UserLoginCache{
		UserId:     userID,
		Username:   req.Username,
		Password:   hashedPassword,
		Salt:       salt,
		LoginLevel: loginLevel,
	}

	go gateway.SetUserLoginCache(loginCache)
	return &pb.GetUIDByUsernameResponse{
		Result: &pb.Result{
			Code: errorcode.Success,
			Msg:  "",
		},
		UserId: userID,
	}, nil
}
