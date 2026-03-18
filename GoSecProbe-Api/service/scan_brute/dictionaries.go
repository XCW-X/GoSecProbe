package scan_brute

var DefaultUsers = map[string][]string{
	"ssh":           {"root", "admin", "ubuntu", "centos", "debian", "pi"},
	"mysql":         {"root", "admin", "mysql"},
	"redis":         {""}, // Redis normally doesn't require user until ACLs in v6
	"postgres":      {"postgres", "root", "admin"},
	"mssql":         {"sa", "admin"},
	"ftp":           {"anonymous", "ftp", "root", "admin"},
	"mongo":         {"", "admin", "root"},
	"rdp":           {"administrator", "admin", "guest"},
	"smb":           {"administrator", "admin", "guest", ""},
	"oracle":        {"system", "sys", "scott", "dba"},
	"telnet":        {"root", "admin", "cisco"},
	"vnc":           {""}, // VNC generally uses password only
	"winrm":         {"administrator", "admin"},
	"elasticsearch": {"elastic"},
	"jenkins":       {"admin", "jenkins"},
	"tomcat":        {"tomcat", "admin", "manager", "role1", "root"},
	"weblogic":      {"weblogic", "system", "admin"},
	"jboss":         {"admin", "jboss"},
	"activemq":      {"admin", "system"},
	"rabbitmq":      {"guest", "admin"},
	"ldap":          {"admin", "Administrator", "root"},
}

var CommonPasswords = []string{
	"", "123456", "12345", "12345678", "123456789", "1234", "password", "root",
	"admin", "123", "admin123", "admin12345", "111111", "000000", "test", "123123",
	"admin@123", "passwd", "root123", "123456aA", "123456Aa", "qwer!@#$1234", "password123",
	"postgres", "sa", "mysql", "qwerty", "test1234", "123456780", "asdfgh", "zxcvbnm",
	"iloveyou", "666666", "888888", "123123123", "cisco", "tiger", "manager", "weblogic",
	"Oracle@123", "weblogic123", "admin1234", "guest", "tomcat",
}

// helper func to get dicts
func getDicts(protocol string) ([]string, []string) {
	users, ok := DefaultUsers[protocol]
	if !ok {
		users = []string{"admin", "root"}
	}
	return users, CommonPasswords
}
