package scanner

import (
	"regexp"
	"strings"
)

// ServiceInfo tespit edilen bir servisin yapılandırılmış bilgisini tutar
type ServiceInfo struct {
	Name    string // Örn: "nginx", "openssh", "mysql"
	Version string // Örn: "1.24.0", "8.9p1"
	Product string // Örn: "Nginx", "OpenSSH", "MySQL"
	Extra   string // Ek bilgi: OS, modül vs.
}

type servicePattern struct {
	Pattern *regexp.Regexp
	Name    string
	Product string
}

// servicePatterns banner/header metinlerinden yazılım+versiyon çıkaran imza veritabanı (300+ imza)
var servicePatterns = []servicePattern{
	// ═══════════════════════════════════════════
	// WEB SUNUCULARI (30+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)nginx[/ ]*(\d[\d.]*)?`), "nginx", "Nginx"},
	{regexp.MustCompile(`(?i)apache[/ ]*(\d[\d.]*)?`), "apache", "Apache HTTP Server"},
	{regexp.MustCompile(`(?i)Microsoft-IIS[/ ]*(\d[\d.]*)?`), "iis", "Microsoft IIS"},
	{regexp.MustCompile(`(?i)LiteSpeed[/ ]*(\d[\d.]*)?`), "litespeed", "LiteSpeed"},
	{regexp.MustCompile(`(?i)lighttpd[/ ]*(\d[\d.]*)?`), "lighttpd", "Lighttpd"},
	{regexp.MustCompile(`(?i)caddy[/ ]*(\d[\d.]*)?`), "caddy", "Caddy Server"},
	{regexp.MustCompile(`(?i)openresty[/ ]*(\d[\d.]*)?`), "openresty", "OpenResty"},
	{regexp.MustCompile(`(?i)gunicorn[/ ]*(\d[\d.]*)?`), "gunicorn", "Gunicorn"},
	{regexp.MustCompile(`(?i)uvicorn[/ ]*(\d[\d.]*)?`), "uvicorn", "Uvicorn"},
	{regexp.MustCompile(`(?i)Werkzeug[/ ]*(\d[\d.]*)?`), "werkzeug", "Werkzeug/Flask"},
	{regexp.MustCompile(`(?i)Kestrel`), "kestrel", "Microsoft Kestrel"},
	{regexp.MustCompile(`(?i)Tomcat[/ ]*(\d[\d.]*)?`), "tomcat", "Apache Tomcat"},
	{regexp.MustCompile(`(?i)Jetty[/ ]*(\d[\d.]*)?`), "jetty", "Eclipse Jetty"},
	{regexp.MustCompile(`(?i)Cherokee[/ ]*(\d[\d.]*)?`), "cherokee", "Cherokee"},
	{regexp.MustCompile(`(?i)Tengine[/ ]*(\d[\d.]*)?`), "tengine", "Tengine"},
	{regexp.MustCompile(`(?i)cloudflare`), "cloudflare", "Cloudflare"},
	{regexp.MustCompile(`(?i)Hiawatha[/ ]*(\d[\d.]*)?`), "hiawatha", "Hiawatha"},
	{regexp.MustCompile(`(?i)Boa[/ ]*(\d[\d.]*)?`), "boa", "Boa HTTPd"},
	{regexp.MustCompile(`(?i)thttpd[/ ]*(\d[\d.]*)?`), "thttpd", "thttpd"},
	{regexp.MustCompile(`(?i)mini_httpd[/ ]*(\d[\d.]*)?`), "mini_httpd", "mini_httpd"},
	{regexp.MustCompile(`(?i)GoAhead[/ ]*(\d[\d.]*)?`), "goahead", "GoAhead WebServer"},
	{regexp.MustCompile(`(?i)Mongoose[/ ]*(\d[\d.]*)?`), "mongoose", "Mongoose WebServer"},
	{regexp.MustCompile(`(?i)WEBrick[/ ]*(\d[\d.]*)?`), "webrick", "WEBrick (Ruby)"},
	{regexp.MustCompile(`(?i)Puma[/ ]*(\d[\d.]*)?`), "puma", "Puma (Ruby)"},
	{regexp.MustCompile(`(?i)Unicorn[/ ]*(\d[\d.]*)?`), "unicorn", "Unicorn (Ruby)"},
	{regexp.MustCompile(`(?i)thin[/ ]*(\d[\d.]*)?`), "thin", "Thin (Ruby)"},
	{regexp.MustCompile(`(?i)Daphne[/ ]*(\d[\d.]*)?`), "daphne", "Daphne (Django)"},
	{regexp.MustCompile(`(?i)Hypercorn[/ ]*(\d[\d.]*)?`), "hypercorn", "Hypercorn (ASGI)"},
	{regexp.MustCompile(`(?i)Waitress[/ ]*(\d[\d.]*)?`), "waitress", "Waitress (Python)"},
	{regexp.MustCompile(`(?i)CherryPy[/ ]*(\d[\d.]*)?`), "cherrypy", "CherryPy"},
	{regexp.MustCompile(`(?i)Cowboy[/ ]*(\d[\d.]*)?`), "cowboy", "Cowboy (Erlang)"},
	{regexp.MustCompile(`(?i)MochiWeb[/ ]*(\d[\d.]*)?`), "mochiweb", "MochiWeb (Erlang)"},
	{regexp.MustCompile(`(?i)Yaws[/ ]*(\d[\d.]*)?`), "yaws", "Yaws (Erlang)"},
	{regexp.MustCompile(`(?i)H2O[/ ]*(\d[\d.]*)?`), "h2o", "H2O HTTP/2 Server"},
	{regexp.MustCompile(`(?i)Traefik[/ ]*(\d[\d.]*)?`), "traefik", "Traefik Proxy"},

	// ═══════════════════════════════════════════
	// UYGULAMA ÇATILARI / API (25+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Express`), "express", "Express.js (Node.js)"},
	{regexp.MustCompile(`(?i)ASP\.NET`), "aspnet", "ASP.NET"},
	{regexp.MustCompile(`(?i)PHP[/ ]*(\d[\d.]*)?`), "php", "PHP"},
	{regexp.MustCompile(`(?i)Phusion Passenger[/ ]*(\d[\d.]*)?`), "passenger", "Phusion Passenger"},
	{regexp.MustCompile(`(?i)Django[/ ]*(\d[\d.]*)?`), "django", "Django"},
	{regexp.MustCompile(`(?i)Flask[/ ]*(\d[\d.]*)?`), "flask", "Flask"},
	{regexp.MustCompile(`(?i)FastAPI[/ ]*(\d[\d.]*)?`), "fastapi", "FastAPI"},
	{regexp.MustCompile(`(?i)Spring[/ ]*(\d[\d.]*)?`), "spring", "Spring Framework"},
	{regexp.MustCompile(`(?i)Laravel`), "laravel", "Laravel (PHP)"},
	{regexp.MustCompile(`(?i)Symfony[/ ]*(\d[\d.]*)?`), "symfony", "Symfony (PHP)"},
	{regexp.MustCompile(`(?i)Ruby on Rails`), "rails", "Ruby on Rails"},
	{regexp.MustCompile(`(?i)Next\.js[/ ]*(\d[\d.]*)?`), "nextjs", "Next.js"},
	{regexp.MustCompile(`(?i)Nuxt[/ ]*(\d[\d.]*)?`), "nuxtjs", "Nuxt.js"},
	{regexp.MustCompile(`(?i)Koa[/ ]*(\d[\d.]*)?`), "koa", "Koa.js"},
	{regexp.MustCompile(`(?i)Fastify[/ ]*(\d[\d.]*)?`), "fastify", "Fastify"},
	{regexp.MustCompile(`(?i)Hapi[/ ]*(\d[\d.]*)?`), "hapi", "Hapi.js"},
	{regexp.MustCompile(`(?i)Gin[/ ]*(\d[\d.]*)?`), "gin", "Gin (Go)"},
	{regexp.MustCompile(`(?i)Echo[/ ]*(\d[\d.]*)?`), "echo", "Echo (Go)"},
	{regexp.MustCompile(`(?i)Fiber[/ ]*(\d[\d.]*)?`), "fiber", "Fiber (Go)"},
	{regexp.MustCompile(`(?i)Actix[/ ]*(\d[\d.]*)?`), "actix", "Actix Web (Rust)"},
	{regexp.MustCompile(`(?i)Rocket[/ ]*(\d[\d.]*)?`), "rocket", "Rocket (Rust)"},
	{regexp.MustCompile(`(?i)Play Framework[/ ]*(\d[\d.]*)?`), "play", "Play Framework"},
	{regexp.MustCompile(`(?i)Vert\.x[/ ]*(\d[\d.]*)?`), "vertx", "Eclipse Vert.x"},
	{regexp.MustCompile(`(?i)Quarkus[/ ]*(\d[\d.]*)?`), "quarkus", "Quarkus"},
	{regexp.MustCompile(`(?i)Micronaut[/ ]*(\d[\d.]*)?`), "micronaut", "Micronaut"},

	// ═══════════════════════════════════════════
	// SSH SUNUCULARI (10+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)OpenSSH[_/ ]*(\d[\d.p]*)?`), "openssh", "OpenSSH"},
	{regexp.MustCompile(`(?i)dropbear[_/ ]*(\d[\d.]*)?`), "dropbear", "Dropbear SSH"},
	{regexp.MustCompile(`(?i)libssh[_/ ]*(\d[\d.]*)?`), "libssh", "libssh"},
	{regexp.MustCompile(`(?i)Bitvise SSH`), "bitvise", "Bitvise SSH"},
	{regexp.MustCompile(`(?i)Paramiko[_/ ]*(\d[\d.]*)?`), "paramiko", "Paramiko SSH"},
	{regexp.MustCompile(`(?i)Tectia SSH`), "tectia", "Tectia SSH"},
	{regexp.MustCompile(`(?i)CrushFTP SSH`), "crushftp-ssh", "CrushFTP SSH"},
	{regexp.MustCompile(`(?i)WinSSHD`), "winsshd", "WinSSHD"},
	{regexp.MustCompile(`(?i)Cisco SSH`), "cisco-ssh", "Cisco SSH"},
	{regexp.MustCompile(`(?i)RomSShell[/ ]*(\d[\d.]*)?`), "romsshell", "AllegroSoft RomSShell"},

	// ═══════════════════════════════════════════
	// FTP SUNUCULARI (15+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)vsftpd[/ ]*(\d[\d.]*)?`), "vsftpd", "vsftpd"},
	{regexp.MustCompile(`(?i)ProFTPD[/ ]*(\d[\d.]*)?`), "proftpd", "ProFTPD"},
	{regexp.MustCompile(`(?i)Pure-FTPd`), "pureftpd", "Pure-FTPd"},
	{regexp.MustCompile(`(?i)FileZilla Server[/ ]*(\d[\d.]*)?`), "filezilla", "FileZilla Server"},
	{regexp.MustCompile(`(?i)Microsoft FTP`), "msftp", "Microsoft FTP Service"},
	{regexp.MustCompile(`(?i)WU-FTPD[/ ]*(\d[\d.]*)?`), "wuftpd", "WU-FTPD"},
	{regexp.MustCompile(`(?i)Serv-U[/ ]*(\d[\d.]*)?`), "servu", "Serv-U FTP"},
	{regexp.MustCompile(`(?i)GlFTPd[/ ]*(\d[\d.]*)?`), "glftpd", "GlFTPd"},
	{regexp.MustCompile(`(?i)Gene6 FTP`), "gene6ftp", "Gene6 FTP Server"},
	{regexp.MustCompile(`(?i)CrushFTP[/ ]*(\d[\d.]*)?`), "crushftp", "CrushFTP"},
	{regexp.MustCompile(`(?i)Titan FTP`), "titanftp", "Titan FTP Server"},
	{regexp.MustCompile(`(?i)War-FTPD[/ ]*(\d[\d.]*)?`), "warftpd", "War-FTPD"},
	{regexp.MustCompile(`(?i)CompleteFTP[/ ]*(\d[\d.]*)?`), "completeftp", "CompleteFTP"},
	{regexp.MustCompile(`(?i)Xlight FTP`), "xlightftp", "Xlight FTP"},
	{regexp.MustCompile(`(?i)bftpd[/ ]*(\d[\d.]*)?`), "bftpd", "bftpd"},

	// ═══════════════════════════════════════════
	// VERİTABANLARI (25+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)mysql[/ ]*(\d[\d.\-]*)?`), "mysql", "MySQL"},
	{regexp.MustCompile(`(?i)MariaDB[/ ]*(\d[\d.\-]*)?`), "mariadb", "MariaDB"},
	{regexp.MustCompile(`(?i)PostgreSQL[/ ]*(\d[\d.]*)?`), "postgresql", "PostgreSQL"},
	{regexp.MustCompile(`(?i)MongoDB[/ ]*(\d[\d.]*)?`), "mongodb", "MongoDB"},
	{regexp.MustCompile(`(?i)Redis[/ :]*(\d[\d.]*)?`), "redis", "Redis"},
	{regexp.MustCompile(`(?i)Elasticsearch[/ ]*(\d[\d.]*)?`), "elasticsearch", "Elasticsearch"},
	{regexp.MustCompile(`(?i)CouchDB[/ ]*(\d[\d.]*)?`), "couchdb", "CouchDB"},
	{regexp.MustCompile(`(?i)Memcached`), "memcached", "Memcached"},
	{regexp.MustCompile(`(?i)Microsoft SQL Server[/ ]*(\d[\d.]*)?`), "mssql", "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)Oracle[\s-]*(Database|TNS)[/ ]*(\d[\d.]*)?`), "oracle", "Oracle Database"},
	{regexp.MustCompile(`(?i)Cassandra[/ ]*(\d[\d.]*)?`), "cassandra", "Apache Cassandra"},
	{regexp.MustCompile(`(?i)CockroachDB[/ ]*(\d[\d.]*)?`), "cockroachdb", "CockroachDB"},
	{regexp.MustCompile(`(?i)InfluxDB[/ ]*(\d[\d.]*)?`), "influxdb", "InfluxDB"},
	{regexp.MustCompile(`(?i)Neo4j[/ ]*(\d[\d.]*)?`), "neo4j", "Neo4j"},
	{regexp.MustCompile(`(?i)RethinkDB[/ ]*(\d[\d.]*)?`), "rethinkdb", "RethinkDB"},
	{regexp.MustCompile(`(?i)ArangoDB[/ ]*(\d[\d.]*)?`), "arangodb", "ArangoDB"},
	{regexp.MustCompile(`(?i)ScyllaDB[/ ]*(\d[\d.]*)?`), "scylladb", "ScyllaDB"},
	{regexp.MustCompile(`(?i)ClickHouse[/ ]*(\d[\d.]*)?`), "clickhouse", "ClickHouse"},
	{regexp.MustCompile(`(?i)TimescaleDB[/ ]*(\d[\d.]*)?`), "timescaledb", "TimescaleDB"},
	{regexp.MustCompile(`(?i)Druid[/ ]*(\d[\d.]*)?`), "druid", "Apache Druid"},
	{regexp.MustCompile(`(?i)TiDB[/ ]*(\d[\d.]*)?`), "tidb", "TiDB"},
	{regexp.MustCompile(`(?i)DynamoDB`), "dynamodb", "AWS DynamoDB"},
	{regexp.MustCompile(`(?i)Firebird[/ ]*(\d[\d.]*)?`), "firebird", "Firebird SQL"},
	{regexp.MustCompile(`(?i)DB2[/ ]*(\d[\d.]*)?`), "db2", "IBM DB2"},
	{regexp.MustCompile(`(?i)Percona[/ ]*(\d[\d.]*)?`), "percona", "Percona Server"},

	// ═══════════════════════════════════════════
	// MAIL SUNUCULARI (15+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Postfix`), "postfix", "Postfix MTA"},
	{regexp.MustCompile(`(?i)Exim[/ ]*(\d[\d.]*)?`), "exim", "Exim MTA"},
	{regexp.MustCompile(`(?i)Dovecot`), "dovecot", "Dovecot IMAP/POP3"},
	{regexp.MustCompile(`(?i)Microsoft Exchange[/ ]*(\d[\d.]*)?`), "exchange", "Microsoft Exchange"},
	{regexp.MustCompile(`(?i)Sendmail[/ ]*(\d[\d.]*)?`), "sendmail", "Sendmail"},
	{regexp.MustCompile(`(?i)Zimbra[/ ]*(\d[\d.]*)?`), "zimbra", "Zimbra"},
	{regexp.MustCompile(`(?i)qmail`), "qmail", "qmail"},
	{regexp.MustCompile(`(?i)Courier[/ ]*(\d[\d.]*)?`), "courier", "Courier MTA"},
	{regexp.MustCompile(`(?i)hMailServer[/ ]*(\d[\d.]*)?`), "hmailserver", "hMailServer"},
	{regexp.MustCompile(`(?i)MailEnable[/ ]*(\d[\d.]*)?`), "mailenable", "MailEnable"},
	{regexp.MustCompile(`(?i)MDaemon[/ ]*(\d[\d.]*)?`), "mdaemon", "MDaemon"},
	{regexp.MustCompile(`(?i)Kerio Connect`), "kerio", "Kerio Connect"},
	{regexp.MustCompile(`(?i)Cyrus[/ ]*(\d[\d.]*)?`), "cyrus", "Cyrus IMAP"},
	{regexp.MustCompile(`(?i)Haraka[/ ]*(\d[\d.]*)?`), "haraka", "Haraka MTA"},
	{regexp.MustCompile(`(?i)OpenSMTPD[/ ]*(\d[\d.]*)?`), "opensmtpd", "OpenSMTPD"},

	// ═══════════════════════════════════════════
	// MESAJ KUYRUKLARI & MIDDLEWARE (15+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)RabbitMQ[/ ]*(\d[\d.]*)?`), "rabbitmq", "RabbitMQ"},
	{regexp.MustCompile(`(?i)ActiveMQ[/ ]*(\d[\d.]*)?`), "activemq", "Apache ActiveMQ"},
	{regexp.MustCompile(`(?i)Kafka[/ ]*(\d[\d.]*)?`), "kafka", "Apache Kafka"},
	{regexp.MustCompile(`(?i)ZeroMQ[/ ]*(\d[\d.]*)?`), "zeromq", "ZeroMQ"},
	{regexp.MustCompile(`(?i)NATS[/ ]*(\d[\d.]*)?`), "nats", "NATS Server"},
	{regexp.MustCompile(`(?i)Mosquitto[/ ]*(\d[\d.]*)?`), "mosquitto", "Eclipse Mosquitto (MQTT)"},
	{regexp.MustCompile(`(?i)EMQ X[/ ]*(\d[\d.]*)?`), "emqx", "EMQX (MQTT)"},
	{regexp.MustCompile(`(?i)VerneMQ[/ ]*(\d[\d.]*)?`), "vernemq", "VerneMQ (MQTT)"},
	{regexp.MustCompile(`(?i)HiveMQ[/ ]*(\d[\d.]*)?`), "hivemq", "HiveMQ (MQTT)"},
	{regexp.MustCompile(`(?i)Pulsar[/ ]*(\d[\d.]*)?`), "pulsar", "Apache Pulsar"},
	{regexp.MustCompile(`(?i)ZooKeeper[/ ]*(\d[\d.]*)?`), "zookeeper", "Apache ZooKeeper"},
	{regexp.MustCompile(`(?i)etcd[/ ]*(\d[\d.]*)?`), "etcd", "etcd"},
	{regexp.MustCompile(`(?i)Consul[/ ]*(\d[\d.]*)?`), "consul", "HashiCorp Consul"},
	{regexp.MustCompile(`(?i)Vault[/ ]*(\d[\d.]*)?`), "vault", "HashiCorp Vault"},
	{regexp.MustCompile(`(?i)Celery[/ ]*(\d[\d.]*)?`), "celery", "Celery"},

	// ═══════════════════════════════════════════
	// CI/CD & DEVOPS ARAÇLARI (20+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Jenkins[/ ]*(\d[\d.]*)?`), "jenkins", "Jenkins CI/CD"},
	{regexp.MustCompile(`(?i)GitLab`), "gitlab", "GitLab"},
	{regexp.MustCompile(`(?i)Gitea[/ ]*(\d[\d.]*)?`), "gitea", "Gitea"},
	{regexp.MustCompile(`(?i)Gogs[/ ]*(\d[\d.]*)?`), "gogs", "Gogs"},
	{regexp.MustCompile(`(?i)Nexus[/ ]*(\d[\d.]*)?`), "nexus", "Sonatype Nexus"},
	{regexp.MustCompile(`(?i)Artifactory[/ ]*(\d[\d.]*)?`), "artifactory", "JFrog Artifactory"},
	{regexp.MustCompile(`(?i)Bamboo[/ ]*(\d[\d.]*)?`), "bamboo", "Atlassian Bamboo"},
	{regexp.MustCompile(`(?i)TeamCity[/ ]*(\d[\d.]*)?`), "teamcity", "JetBrains TeamCity"},
	{regexp.MustCompile(`(?i)GoCD[/ ]*(\d[\d.]*)?`), "gocd", "GoCD"},
	{regexp.MustCompile(`(?i)Drone[/ ]*(\d[\d.]*)?`), "drone", "Drone CI"},
	{regexp.MustCompile(`(?i)Concourse[/ ]*(\d[\d.]*)?`), "concourse", "Concourse CI"},
	{regexp.MustCompile(`(?i)Harbor[/ ]*(\d[\d.]*)?`), "harbor", "Harbor Registry"},
	{regexp.MustCompile(`(?i)SonarQube[/ ]*(\d[\d.]*)?`), "sonarqube", "SonarQube"},
	{regexp.MustCompile(`(?i)Sentry[/ ]*(\d[\d.]*)?`), "sentry", "Sentry"},
	{regexp.MustCompile(`(?i)Portainer[/ ]*(\d[\d.]*)?`), "portainer", "Portainer"},
	{regexp.MustCompile(`(?i)Rancher[/ ]*(\d[\d.]*)?`), "rancher", "Rancher"},
	{regexp.MustCompile(`(?i)Argo CD`), "argocd", "Argo CD"},
	{regexp.MustCompile(`(?i)Grafana[/ ]*(\d[\d.]*)?`), "grafana", "Grafana"},
	{regexp.MustCompile(`(?i)Kibana[/ ]*(\d[\d.]*)?`), "kibana", "Kibana"},
	{regexp.MustCompile(`(?i)Prometheus[/ ]*(\d[\d.]*)?`), "prometheus", "Prometheus"},

	// ═══════════════════════════════════════════
	// CONTAINER & ORCHESTRATION (10+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Docker[/ ]*(\d[\d.]*)?`), "docker", "Docker Engine"},
	{regexp.MustCompile(`(?i)Kubernetes`), "kubernetes", "Kubernetes API"},
	{regexp.MustCompile(`(?i)Nomad[/ ]*(\d[\d.]*)?`), "nomad", "HashiCorp Nomad"},
	{regexp.MustCompile(`(?i)Podman[/ ]*(\d[\d.]*)?`), "podman", "Podman"},
	{regexp.MustCompile(`(?i)Containerd[/ ]*(\d[\d.]*)?`), "containerd", "containerd"},
	{regexp.MustCompile(`(?i)CRI-O[/ ]*(\d[\d.]*)?`), "crio", "CRI-O"},
	{regexp.MustCompile(`(?i)Envoy[/ ]*(\d[\d.]*)?`), "envoy", "Envoy Proxy"},
	{regexp.MustCompile(`(?i)Istio[/ ]*(\d[\d.]*)?`), "istio", "Istio"},
	{regexp.MustCompile(`(?i)Linkerd[/ ]*(\d[\d.]*)?`), "linkerd", "Linkerd"},

	// ═══════════════════════════════════════════
	// AĞ CİHAZLARI & PROTOKOLLER (20+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Cisco[/ ]*(\d[\d.]*)?`), "cisco", "Cisco IOS"},
	{regexp.MustCompile(`(?i)MikroTik[/ ]*(\d[\d.]*)?`), "mikrotik", "MikroTik RouterOS"},
	{regexp.MustCompile(`(?i)Ubiquiti`), "ubiquiti", "Ubiquiti"},
	{regexp.MustCompile(`(?i)Juniper[/ ]*(\d[\d.]*)?`), "juniper", "Juniper Networks"},
	{regexp.MustCompile(`(?i)FortiOS[/ ]*(\d[\d.]*)?`), "fortios", "FortiGate FortiOS"},
	{regexp.MustCompile(`(?i)pfSense`), "pfsense", "pfSense"},
	{regexp.MustCompile(`(?i)OPNsense`), "opnsense", "OPNsense"},
	{regexp.MustCompile(`(?i)OpenWrt`), "openwrt", "OpenWrt"},
	{regexp.MustCompile(`(?i)DD-WRT`), "ddwrt", "DD-WRT"},
	{regexp.MustCompile(`(?i)Aruba[/ ]*(\d[\d.]*)?`), "aruba", "Aruba Networks"},
	{regexp.MustCompile(`(?i)Palo Alto`), "paloalto", "Palo Alto Networks"},
	{regexp.MustCompile(`(?i)SonicWALL`), "sonicwall", "SonicWall"},
	{regexp.MustCompile(`(?i)WatchGuard`), "watchguard", "WatchGuard"},
	{regexp.MustCompile(`(?i)Barracuda`), "barracuda", "Barracuda Networks"},
	{regexp.MustCompile(`(?i)F5 BIG-IP`), "f5bigip", "F5 BIG-IP"},
	{regexp.MustCompile(`(?i)Citrix[/ ]*(\d[\d.]*)?`), "citrix", "Citrix ADC/NetScaler"},
	{regexp.MustCompile(`(?i)ISC BIND[/ ]*(\d[\d.]*)?`), "bind", "ISC BIND DNS"},
	{regexp.MustCompile(`(?i)Unbound[/ ]*(\d[\d.]*)?`), "unbound", "Unbound DNS"},
	{regexp.MustCompile(`(?i)PowerDNS[/ ]*(\d[\d.]*)?`), "powerdns", "PowerDNS"},
	{regexp.MustCompile(`(?i)dnsmasq[/ ]*(\d[\d.]*)?`), "dnsmasq", "dnsmasq"},

	// ═══════════════════════════════════════════
	// PROXY & LOAD BALANCER (10+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)HAProxy[/ ]*(\d[\d.]*)?`), "haproxy", "HAProxy"},
	{regexp.MustCompile(`(?i)Varnish[/ ]*(\d[\d.]*)?`), "varnish", "Varnish Cache"},
	{regexp.MustCompile(`(?i)Squid[/ ]*(\d[\d.]*)?`), "squid", "Squid Proxy"},
	{regexp.MustCompile(`(?i)Pound[/ ]*(\d[\d.]*)?`), "pound", "Pound Proxy"},
	{regexp.MustCompile(`(?i)Apache Traffic Server[/ ]*(\d[\d.]*)?`), "ats", "Apache Traffic Server"},
	{regexp.MustCompile(`(?i)Akamai`), "akamai", "Akamai CDN"},
	{regexp.MustCompile(`(?i)Fastly`), "fastly", "Fastly CDN"},
	{regexp.MustCompile(`(?i)KeyCDN`), "keycdn", "KeyCDN"},
	{regexp.MustCompile(`(?i)MaxCDN`), "maxcdn", "MaxCDN/StackPath"},
	{regexp.MustCompile(`(?i)Amazon CloudFront`), "cloudfront", "AWS CloudFront"},

	// ═══════════════════════════════════════════
	// DEPOLAMA & DOSYA SERVİSLERİ (10+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Minio[/ ]*(\d[\d.]*)?`), "minio", "MinIO Object Storage"},
	{regexp.MustCompile(`(?i)Samba[/ ]*(\d[\d.]*)?`), "samba", "Samba (SMB/CIFS)"},
	{regexp.MustCompile(`(?i)NFS[/ ]*(\d[\d.]*)?`), "nfs", "NFS Server"},
	{regexp.MustCompile(`(?i)GlusterFS[/ ]*(\d[\d.]*)?`), "glusterfs", "GlusterFS"},
	{regexp.MustCompile(`(?i)Ceph[/ ]*(\d[\d.]*)?`), "ceph", "Ceph Storage"},
	{regexp.MustCompile(`(?i)Nextcloud[/ ]*(\d[\d.]*)?`), "nextcloud", "Nextcloud"},
	{regexp.MustCompile(`(?i)ownCloud[/ ]*(\d[\d.]*)?`), "owncloud", "ownCloud"},
	{regexp.MustCompile(`(?i)Seafile[/ ]*(\d[\d.]*)?`), "seafile", "Seafile"},
	{regexp.MustCompile(`(?i)WebDAV`), "webdav", "WebDAV"},
	{regexp.MustCompile(`(?i)Synology`), "synology", "Synology DSM"},
	{regexp.MustCompile(`(?i)QNAP`), "qnap", "QNAP NAS"},

	// ═══════════════════════════════════════════
	// GÜVENLİK & KİMLİK DOĞRULAMA (15+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)OpenVPN[/ ]*(\d[\d.]*)?`), "openvpn", "OpenVPN"},
	{regexp.MustCompile(`(?i)WireGuard`), "wireguard", "WireGuard VPN"},
	{regexp.MustCompile(`(?i)StrongSwan[/ ]*(\d[\d.]*)?`), "strongswan", "strongSwan IPsec"},
	{regexp.MustCompile(`(?i)OpenLDAP[/ ]*(\d[\d.]*)?`), "openldap", "OpenLDAP"},
	{regexp.MustCompile(`(?i)Active Directory`), "ad", "Active Directory"},
	{regexp.MustCompile(`(?i)FreeRADIUS[/ ]*(\d[\d.]*)?`), "freeradius", "FreeRADIUS"},
	{regexp.MustCompile(`(?i)Keycloak[/ ]*(\d[\d.]*)?`), "keycloak", "Keycloak IAM"},
	{regexp.MustCompile(`(?i)Authentik`), "authentik", "Authentik IdP"},
	{regexp.MustCompile(`(?i)Dex[/ ]*(\d[\d.]*)?`), "dex", "Dex OIDC"},
	{regexp.MustCompile(`(?i)CAS[/ ]*(\d[\d.]*)?`), "cas", "Apereo CAS"},
	{regexp.MustCompile(`(?i)Snort[/ ]*(\d[\d.]*)?`), "snort", "Snort IDS/IPS"},
	{regexp.MustCompile(`(?i)Suricata[/ ]*(\d[\d.]*)?`), "suricata", "Suricata IDS/IPS"},
	{regexp.MustCompile(`(?i)OSSEC[/ ]*(\d[\d.]*)?`), "ossec", "OSSEC HIDS"},
	{regexp.MustCompile(`(?i)Wazuh[/ ]*(\d[\d.]*)?`), "wazuh", "Wazuh SIEM"},
	{regexp.MustCompile(`(?i)Fail2Ban`), "fail2ban", "Fail2Ban"},

	// ═══════════════════════════════════════════
	// IoT & SCADA (10+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Modbus`), "modbus", "Modbus Protocol"},
	{regexp.MustCompile(`(?i)BACnet`), "bacnet", "BACnet Protocol"},
	{regexp.MustCompile(`(?i)S7comm`), "s7comm", "Siemens S7comm"},
	{regexp.MustCompile(`(?i)DNP3`), "dnp3", "DNP3 Protocol"},
	{regexp.MustCompile(`(?i)EtherNet/IP`), "ethernetip", "EtherNet/IP"},
	{regexp.MustCompile(`(?i)OPC[- ]?UA`), "opcua", "OPC UA"},
	{regexp.MustCompile(`(?i)CoAP`), "coap", "CoAP (IoT)"},
	{regexp.MustCompile(`(?i)AMQP`), "amqp", "AMQP Protocol"},
	{regexp.MustCompile(`(?i)Telnet`), "telnet", "Telnet"},
	{regexp.MustCompile(`(?i)RTSP[/ ]*(\d[\d.]*)?`), "rtsp", "RTSP (Streaming)"},

	// ═══════════════════════════════════════════
	// DİĞER (20+)
	// ═══════════════════════════════════════════
	{regexp.MustCompile(`(?i)Elasticsearch[/ ]*(\d[\d.]*)?`), "elasticsearch", "Elasticsearch"},
	{regexp.MustCompile(`(?i)Solr[/ ]*(\d[\d.]*)?`), "solr", "Apache Solr"},
	{regexp.MustCompile(`(?i)Splunk[/ ]*(\d[\d.]*)?`), "splunk", "Splunk"},
	{regexp.MustCompile(`(?i)Logstash[/ ]*(\d[\d.]*)?`), "logstash", "Logstash"},
	{regexp.MustCompile(`(?i)Puppet[/ ]*(\d[\d.]*)?`), "puppet", "Puppet"},
	{regexp.MustCompile(`(?i)Ansible Tower`), "ansible", "Ansible Tower/AWX"},
	{regexp.MustCompile(`(?i)SaltStack[/ ]*(\d[\d.]*)?`), "saltstack", "SaltStack"},
	{regexp.MustCompile(`(?i)Zabbix[/ ]*(\d[\d.]*)?`), "zabbix", "Zabbix"},
	{regexp.MustCompile(`(?i)Nagios[/ ]*(\d[\d.]*)?`), "nagios", "Nagios"},
	{regexp.MustCompile(`(?i)Icinga[/ ]*(\d[\d.]*)?`), "icinga", "Icinga"},
	{regexp.MustCompile(`(?i)Cacti[/ ]*(\d[\d.]*)?`), "cacti", "Cacti"},
	{regexp.MustCompile(`(?i)phpMyAdmin[/ ]*(\d[\d.]*)?`), "phpmyadmin", "phpMyAdmin"},
	{regexp.MustCompile(`(?i)Adminer[/ ]*(\d[\d.]*)?`), "adminer", "Adminer"},
	{regexp.MustCompile(`(?i)pgAdmin[/ ]*(\d[\d.]*)?`), "pgadmin", "pgAdmin"},
	{regexp.MustCompile(`(?i)Webmin[/ ]*(\d[\d.]*)?`), "webmin", "Webmin"},
	{regexp.MustCompile(`(?i)Cockpit`), "cockpit", "Cockpit Web Console"},
	{regexp.MustCompile(`(?i)cPanel[/ ]*(\d[\d.]*)?`), "cpanel", "cPanel"},
	{regexp.MustCompile(`(?i)Plesk[/ ]*(\d[\d.]*)?`), "plesk", "Plesk"},
	{regexp.MustCompile(`(?i)ISPConfig[/ ]*(\d[\d.]*)?`), "ispconfig", "ISPConfig"},
	{regexp.MustCompile(`(?i)DirectAdmin[/ ]*(\d[\d.]*)?`), "directadmin", "DirectAdmin"},
	{regexp.MustCompile(`(?i)Roundcube`), "roundcube", "Roundcube Webmail"},
	{regexp.MustCompile(`(?i)WordPress[/ ]*(\d[\d.]*)?`), "wordpress", "WordPress"},
	{regexp.MustCompile(`(?i)Joomla[/ ]*(\d[\d.]*)?`), "joomla", "Joomla CMS"},
	{regexp.MustCompile(`(?i)Drupal[/ ]*(\d[\d.]*)?`), "drupal", "Drupal CMS"},
	{regexp.MustCompile(`(?i)Magento[/ ]*(\d[\d.]*)?`), "magento", "Magento"},
}

// IdentifyService banner/header metnini servis imza veritabanıyla karşılaştırarak
// yazılım adı ve versiyonunu tespit eder
func IdentifyService(banner string) ServiceInfo {
	if banner == "" {
		return ServiceInfo{}
	}

	for _, sp := range servicePatterns {
		matches := sp.Pattern.FindStringSubmatch(banner)
		if matches != nil {
			version := ""
			if len(matches) > 1 {
				version = strings.TrimSpace(matches[1])
			}
			extra := ""
			if strings.Contains(strings.ToLower(banner), "asp.net") && sp.Name != "aspnet" {
				extra = "ASP.NET backend"
			}
			return ServiceInfo{
				Name:    sp.Name,
				Version: version,
				Product: sp.Product,
				Extra:   extra,
			}
		}
	}

	return ServiceInfo{Name: "unknown", Product: "Unknown Service"}
}

// DisplayName servis için okunabilir bir etiket üretir (Örn: "Nginx 1.24.0")
func (s ServiceInfo) DisplayName() string {
	if s.Product == "" {
		return "Unknown"
	}
	if s.Version != "" {
		return s.Product + " " + s.Version
	}
	return s.Product
}

// shieldedServices CDN, WAF, DDoS koruması ve reverse proxy servisleri listesi.
// Bu servisler arkadaki gerçek uygulamayı maskeler; banner'ları NVD'ye sorgulandığında
// alakasız CVE'ler döner (false positive). Tespit edildiğinde CVE/exploit sorgusu atlanır.
var shieldedServices = map[string]string{
	// CDN Providers
	"cloudflare":    "Cloudflare CDN/WAF",
	"akamai":        "Akamai CDN",
	"fastly":        "Fastly CDN",
	"cloudfront":    "Amazon CloudFront",
	"keycdn":        "KeyCDN",
	"maxcdn":        "MaxCDN/StackPath",
	"stackpath":     "StackPath CDN",
	"cdn77":         "CDN77",
	"bunnycdn":      "BunnyCDN",
	"azurecdn":      "Azure CDN",
	"googlecdn":     "Google Cloud CDN",
	// WAF / DDoS Protection
	"sucuri":        "Sucuri WAF",
	"incapsula":     "Imperva Incapsula",
	"imperva":       "Imperva WAF",
	"barracuda-waf": "Barracuda WAF",
	"f5-bigip":      "F5 BIG-IP",
	"fortiweb":      "FortiWeb WAF",
	"wallarm":       "Wallarm WAF",
	"modsecurity":   "ModSecurity WAF",
	"aws-waf":       "AWS WAF",
	"azure-waf":     "Azure WAF",
	// Reverse Proxy / Edge
	"varnish":       "Varnish Cache",
	"squid-proxy":   "Squid Proxy",
	"envoy":         "Envoy Proxy",
	"traefik":       "Traefik Proxy",
}

// IsShieldedService tespit edilen servisin CDN/WAF/reverse proxy olup olmadığını kontrol eder.
// Banner metninde bu servislerin izi varsa true döner.
func IsShieldedService(svc ServiceInfo, banner string) (bool, string) {
	// Önce servis adına bak
	nameLower := strings.ToLower(svc.Name)
	if desc, ok := shieldedServices[nameLower]; ok {
		return true, desc
	}

	// Banner metninde CDN/WAF izleri ara
	bannerLower := strings.ToLower(banner)
	cdnSignatures := []struct {
		keyword string
		name    string
	}{
		{"cloudflare", "Cloudflare CDN/WAF"},
		{"cf-ray", "Cloudflare CDN/WAF"},
		{"cf-cache", "Cloudflare CDN/WAF"},
		{"akamai", "Akamai CDN"},
		{"akamaighost", "Akamai CDN"},
		{"fastly", "Fastly CDN"},
		{"cloudfront", "Amazon CloudFront"},
		{"x-amz-cf", "Amazon CloudFront"},
		{"sucuri", "Sucuri WAF"},
		{"incapsula", "Imperva Incapsula"},
		{"imperva", "Imperva WAF"},
		{"stackpath", "StackPath CDN"},
		{"varnish", "Varnish Cache"},
		{"x-varnish", "Varnish Cache"},
		{"keycdn", "KeyCDN"},
		{"bunnycdn", "BunnyCDN"},
		{"ddos-guard", "DDoS-Guard"},
		{"barracuda", "Barracuda WAF"},
		{"fortiweb", "FortiWeb WAF"},
		{"wallarm", "Wallarm WAF"},
	}

	for _, sig := range cdnSignatures {
		if strings.Contains(bannerLower, sig.keyword) {
			return true, sig.name
		}
	}

	return false, ""
}
