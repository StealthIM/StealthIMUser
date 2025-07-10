package errorcode

const (
	// UserInternalError 一般内部错误
	UserInternalError int32 = 1200 + iota
	// UserNotFound 用户不存在
	UserNotFound
	// UserAlreadyExists 用户已存在
	UserAlreadyExists
	// UserPasswordError 用户密码错误
	UserPasswordError
	// UserPermissionDenied 用户权限不足
	UserPermissionDenied
	// UserInvalidParameter 用户参数错误
	UserInvalidParameter
)
