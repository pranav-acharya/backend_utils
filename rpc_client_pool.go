package backend_utils

import (
	"google.golang.org/grpc"
	"errors"
	"log"
	"io"
)

const (
	PKG_NAME = "RpcClientPool"
	VERSION = "1.1"
)

var (
	ERR_FATAL error = errors.New("Fatal error.")
)

type ConnEndpointInfo struct {
	Tls bool
	CertFile string
	ServerHostOverride string
	ServerAddr string
}

type RpcClientPool struct {
	doHeartBeat func(*grpc.ClientConn) error
	conn_pool chan *grpc.ClientConn
	conn_endpoints map[*grpc.ClientConn] int
	endpoints_map map[int] interface{}
	elog *log.Logger
	ilog *log.Logger
	pool_created bool
}

func (r *RpcClientPool) createPool(endpoints []interface{}, conn_per_ep int) error {

	if len(endpoints) == 0 || conn_per_ep == 0 {
		r.elog.Println("Failed creating conn pool.")
		return ERR_FATAL
	}

	r.conn_endpoints = make(map[*grpc.ClientConn] int, conn_per_ep * len(endpoints))
	r.conn_pool = make(chan *grpc.ClientConn, conn_per_ep * len(endpoints))
	r.endpoints_map = make(map[int] interface{}, len(endpoints))

	for i := range endpoints {
		r.endpoints_map[i] = endpoints[i]
		for j := 0; j < conn_per_ep; j++ {
			new_conn, err := r.newRPCConn(endpoints[i])
			if err != nil {
				r.elog.Printf("Failed creating connection Ep: %+v. Err:%s\n", endpoints[i], err.Error())
				continue
			}
			r.conn_endpoints[new_conn] = i
			r.Put(new_conn)
			r.ilog.Printf("Successfully created new connection to Ep:%+v\n", endpoints[i])
		}
	}
	if len(r.conn_endpoints) == 0 {
		r.elog.Println("Failed creating any connection.")
		return ERR_FATAL
	}
	r.pool_created = true
	return nil
}

func (r *RpcClientPool) newRPCConn(ep interface{}) (*grpc.ClientConn, error) {

	var cli *GrpcClientConfig

	switch ep.(type) {
	case ConnEndpointInfo:
		cli = &GrpcClientConfig{
			UseTls: ep.(ConnEndpointInfo).Tls,
			ServerHostOverride: ep.(ConnEndpointInfo).ServerHostOverride,
			ServerAddr: ep.(ConnEndpointInfo).ServerAddr,
			UseJwt: false,
		}
		break
	case GrpcClientConfig:
		cli = &GrpcClientConfig{
			UseTls: ep.(GrpcClientConfig).UseTls,
			ServerHostOverride: ep.(GrpcClientConfig).ServerHostOverride,
			ServerAddr: ep.(GrpcClientConfig).ServerAddr,
			UseJwt: ep.(GrpcClientConfig).UseJwt,
			JwtToken: ep.(GrpcClientConfig).JwtToken,
		}
		break
	}

	conn, err := cli.NewRPCConn()
	if err != nil {
		r.elog.Printf("Failed to dial. ERR:%s\n", err.Error())
		return nil, err
	}

	r.ilog.Printf("Established new RPC connection to %s.\n", cli.ServerAddr)
	return conn, nil
}

func NewRpcClientPool(do_heartbeat func(*grpc.ClientConn) error, endpoints []interface{},
		      conn_per_ep int, logr_op io.Writer) *RpcClientPool {
	client_pool := new(RpcClientPool)
	client_pool.doHeartBeat = do_heartbeat
	client_pool.initLogger(logr_op)
	if err := client_pool.createPool(endpoints, conn_per_ep); err != nil {
		client_pool.elog.Printf("Failed to create RPC pool. ERR:%s\n", err.Error())
		return nil
	}
	return client_pool
}

func (r *RpcClientPool) initLogger(logger_op io.Writer)  {
	err_prefix := PKG_NAME + ":" + VERSION + "\tERROR\t"
	info_prefix := PKG_NAME + ":" + VERSION + "\tINFO\t"

	r.elog = log.New(logger_op, err_prefix, log.Ldate|log.Ltime|log.Lshortfile)
	r.ilog = log.New(logger_op, info_prefix, log.Ldate|log.Ltime|log.Lshortfile)
}

func (r *RpcClientPool) Get() *grpc.ClientConn {
	if len(r.conn_endpoints) == 0 {
		r.elog.Println("No more connections in map.")
		return nil
	}
	var conn *grpc.ClientConn
	select {
	case conn = <- r.conn_pool:
		if err := r.doHeartBeat(conn); err != nil {
			ep := r.conn_endpoints[conn]
			delete(r.conn_endpoints, conn)
			conn, err = r.newRPCConn(r.endpoints_map[ep])
			if err != nil {
				r.elog.Printf("Failed to re-establish connection. Ep:%+v ERR:%s\n", ep, err.Error())
				// Try to get another connection.
				return r.Get()
			}
			r.conn_endpoints[conn] = ep
		}
	default:
	}
	return conn
}


func (r *RpcClientPool) Put(conn *grpc.ClientConn) {
	select {
	case r.conn_pool <- conn:
	default:
	}
}
