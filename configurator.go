package backend_utils

import (
	"encoding/json"
	"os"
	"log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/grpc-ecosystem/go-grpc-middleware/validator"
	"io/ioutil"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"fmt"
	"google.golang.org/grpc/metadata"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"database/sql"
	"errors"
)

type GrpcServerConfig struct {

	// Use TLS for encryption
	UseTls 		bool	`json:"use_tls"`
	CertFile 	string	`json:"cert_file"`
	KeyFile 	string 	`json:"key_file"`

	// Use JWT based authentication
	UseJwt		bool	`json:"use_jwt"`
	PubKeyFile	string	`json:"pub_key"`
	PrivKeyFile	string	`json:"priv_key"`

	UseValidator	bool	`json:"use_validator"`
	Port		int32	`json:"port"`
	LogLevel	int32	`json:"log_level"`

	// Non-json fields
	PubKey		*rsa.PublicKey
	PrivKey		*rsa.PrivateKey
	auth_func_set	bool
	auth_func 	func (context.Context) (context.Context, error)
}

type GrpcClientConfig struct {

	// Use TLS for encryption
	UseTls 			bool	`json:"use_tls"`
	CertFile 		string	`json:"cert_file"`

	UseJwt			bool	`json:"use_jwt"`

	ServerHostOverride 	string	`json:"server_host_override"`
	ServerAddr 		string	`json:"server_addr"`

	// Non-json fields
	JwtToken		string
}

type PostgresDBConfig struct {
	Username	string	`json:"username"`
	Password	string	`json:"password"`
	DBName		string	`json:"db_name"`
}

type EmailerConfig struct {
	SmtpAddr	string	`json:"smtp_addr"`
	SmtpPort	int	`json:"smtp_port"`
	Username	string	`json:"username"`
	Password	string	`json:"password"`
}

type Configurations struct {
	ServerConfig	GrpcServerConfig 	`json:"server_config"`
	ClientConfig 	[]GrpcClientConfig	`json:"client_config"`
	PostgresDB	PostgresDBConfig	`json:"postgres_db"`
	Emailer		EmailerConfig		`json:"emailer"`
	AuthConfig 	GrpcClientConfig	`json:"auth_config"`
}

func ReadConfFile(file_path string) (*Configurations, error) {

	file, err := os.Open(file_path)
	if err != nil {
		return nil, err
	}

	conf := new(Configurations)

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&conf)
	if err != nil {
		return nil, err
	}

	log.Printf("Read Configurations:%v\n", conf)

	return conf, nil
}

func ParseJWTpubKeyFile(file_path string) (*rsa.PublicKey, error) {
	key, err := ioutil.ReadFile(file_path)
	if err != nil {
		log.Printf("Failed reading JWT public key file.ERR:%s\n", err)
		return nil, err
	}
	pub_key, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		log.Printf("Failed parsing public key.ERR:%s\n", err)
		return nil, err
	}
	return pub_key, nil
}

func ParseJWTprivKeyFile(file_path string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(file_path)
	if err != nil {
		log.Printf("Failed reading JWT public key file.ERR:%s\n", err)
		return nil, err
	}
	priv_key, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Printf("Failed parsing public key.ERR:%s\n", err)
		return nil, err
	}
	return priv_key, nil
}

func validateToken(token string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			log.Printf("Unexpected signing method: %v", t.Header["alg"])
			return nil, fmt.Errorf("Invalid token %s", token)
		}
		return publicKey, nil
	})
	if err == nil && jwtToken.Valid {
		return jwtToken, nil
	}
	return nil, err
}

func (c *GrpcServerConfig) DefaultAuthFunction(ctx context.Context) (context.Context, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrUnauthenticated("Metadata corrupted")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, ErrUnauthenticated("Authorization header not present")
	}

	token, err := validateToken(jwtToken[0], c.PubKey)
	if err != nil {
		return nil, ErrUnauthenticated("Invalid token")
	}

	newCtx := context.WithValue(ctx, "jwt_token", token)
	return newCtx, nil
}

func (c *GrpcServerConfig) WithAuthFunc(auth func (context.Context) (context.Context, error)) {

	if !c.UseJwt {
		log.Fatal("Public key file not specified in config.")
	}

	var err error
	c.PubKey, err = ParseJWTpubKeyFile(c.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.auth_func = auth
	c.auth_func_set = true
}

func (c *GrpcServerConfig) withDefaultAuthFunc() {

	var err error
	c.PubKey, err = ParseJWTpubKeyFile(c.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.auth_func = c.DefaultAuthFunction
	c.auth_func_set = true
}

func (c *GrpcServerConfig) GetServerOpts() ([]grpc.ServerOption, error) {

	var opts []grpc.ServerOption

	if c.UseTls {
		creds, err := credentials.NewServerTLSFromFile(c.CertFile, c.KeyFile)
		if err != nil {
			log.Printf("Failed creating TLS credentials.ERR:%s\n", err)
			return opts, err
		}

		opts = append(opts, grpc.Creds(creds))
	}

	if c.UseJwt {
		if !c.auth_func_set {
			c.withDefaultAuthFunc()
		}
		opts = append(opts, grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(c.auth_func)))
		opts = append(opts, grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(c.auth_func)))

	}

	if c.UseValidator {
		opts = append(opts, grpc.StreamInterceptor(grpc_validator.StreamServerInterceptor()))
		opts = append(opts, grpc.UnaryInterceptor(grpc_validator.UnaryServerInterceptor()))
	}

	return opts, nil
}

type JwtCredentials struct {
	credentials.PerRPCCredentials
	token string
}

func NewJwtCredentials(tok string) *JwtCredentials {
	creds := new(JwtCredentials)
	creds.token = tok
	return creds
}

// GetRequestMetadata gets the current request metadata
func (j *JwtCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {

	return map[string]string{
		"authorization": j.token,
	}, nil
}

// Jwt does not RequireTransportSecurity
func (j *JwtCredentials) RequireTransportSecurity() bool { return false }

func (c *GrpcClientConfig) WithJWTToken(token string) *GrpcClientConfig {
	c.JwtToken = token
	return c
}

func (c *GrpcClientConfig) NewRPCConn() (*grpc.ClientConn, error) {

	opts, err := c.GetClientOpts()
	if err != nil {
		log.Printf("Failed to get client options. ERR:%s\n", err.Error())
		return nil, err
	}

	if len(opts) == 0 {
		opts = []grpc.DialOption{
			grpc.WithInsecure(),
		}
	}

	conn, err := grpc.Dial(c.ServerAddr, opts...)
	if err != nil {
		log.Printf("Failed to dial. ERR:%s\n", err.Error())
		return nil, err
	}

	return conn, nil
}

func (c *GrpcClientConfig) GetClientOpts() ([]grpc.DialOption, error) {

	var opts []grpc.DialOption
	if c.UseTls {
		var sn string
		if c.ServerHostOverride != "" {
			sn = c.ServerHostOverride
		}

		var creds credentials.TransportCredentials
		if c.CertFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(c.CertFile, sn)
			if err != nil {
				log.Printf("Failed to create TLS credentials. ERR:%s\n", err.Error())
				return nil, err
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	if c.UseJwt {
		if len(c.JwtToken) == 0 {
			log.Println("Token not specified for JWT.")
			return nil, errors.New("Token not specified for use of JWT.")
		}
		opts = append(opts, grpc.WithPerRPCCredentials(NewJwtCredentials(c.JwtToken)))
	}

	return opts, nil
}

func (dbConf *PostgresDBConfig) OpenDB() (*sql.DB, error) {

	dbP, err := sql.Open("postgres", "user=" + dbConf.Username + " dbname=" + dbConf.DBName +
			     " sslmode=disable")
	if err == nil {
		// Open doesn't really do anything. Ping is where we will know.
		err = dbP.Ping()
	}

	if err != nil {
		log.Printf("Failed opening DB Err:%s", err.Error())
		return nil, err
	}

	return dbP, nil
}

func (dbConf *PostgresDBConfig) CreatePQDB() (*sql.DB, error) {

	// If DB is already created, Use the same.
	dbP, err := dbConf.OpenDB()
	if err == nil {
		log.Println("DB has already been created.")
		return dbP, nil
	}

	cmd_result := ExecCommand("psql", "-U" + dbConf.Username, "-tc CREATE DATABASE " + dbConf.DBName)
	if cmd_result.Err != nil {
		log.Printf("Failed executing database create command Err:%s", cmd_result.Err.Error())
		return nil, cmd_result.Err
	}

	log.Printf("Database command result: OUT:%s ERR:%s", cmd_result.StdOut, cmd_result.StdErr)
	if len(cmd_result.StdErr) > 0 {
		log.Printf("Database create command retured error. %s", cmd_result.StdErr)
		return nil, errors.New(cmd_result.StdErr)
	}

	return dbConf.OpenDB()
}
