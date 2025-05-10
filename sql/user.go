package sql

const (
	// User authentication SQL
	CheckUserSQL = `
		SELECT a.uid, a.username, a.nickname, a.password, a.salt, a.login_level, 
		i.email, i.phone_number, i.create_time, i.vip 
		FROM user_auth a
		LEFT JOIN user_info i ON a.uid = i.uid
		WHERE a.username = ? AND a.login_level = 0;
	`

	// User registration SQL - user_auth table
	InsertUserAuthSQL = `
		INSERT INTO user_auth (username, nickname, password, salt, login_level) 
		VALUES (?, ?, ?, ?, 0);
	`

	// User registration SQL - user_info table
	InsertUserInfoSQL = `
		INSERT INTO user_info (uid, email, phone_number) 
		VALUES (?, ?, ?);
	`

	// Get user info SQL
	GetUserInfoSQL = `
		SELECT a.uid, a.username, a.nickname, a.login_level,
		i.email, i.phone_number, i.create_time, i.vip 
		FROM user_auth a
		LEFT JOIN user_info i ON a.uid = i.uid
		WHERE a.uid = ? AND a.login_level = 0;
	`

	// Get other user info SQL
	GetOtherUserInfoSQL = `
		SELECT a.uid, a.nickname, i.vip
		FROM user_auth a
		LEFT JOIN user_info i ON a.uid = i.uid
		WHERE a.uid = ? AND a.login_level = 0;
	`

	// Update user status SQL
	UpdateUserStatusSQL = `
		UPDATE user_auth SET login_level = ? WHERE uid = ?;
	`

	// Update user password SQL
	UpdateUserPasswordSQL = `
		UPDATE user_auth SET password = ?, salt = ? WHERE uid = ?;
	`

	// Update user nickname SQL
	UpdateUserNicknameSQL = `
		UPDATE user_auth SET nickname = ? WHERE uid = ?;
	`

	// Update user email SQL
	UpdateUserEmailSQL = `
		UPDATE user_info SET email = ? WHERE uid = ?;
	`

	// Update user phone number SQL
	UpdateUserPhoneNumberSQL = `
		UPDATE user_info SET phone_number = ? WHERE uid = ?;
	`

	// Update user login level SQL
	UpdateUserLoginLevelSQL = `
		UPDATE user_auth SET login_level = ? WHERE uid = ?;
	`
)
