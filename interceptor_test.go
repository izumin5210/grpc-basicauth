package grpcbasicauth

import (
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/testing"
	pb_testproto "github.com/grpc-ecosystem/go-grpc-middleware/testing/testproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ping = &pb_testproto.PingRequest{Value: "something", SleepTimeMs: 9999}
)

type authTestSuite struct {
	*grpc_testing.InterceptorTestSuite
	username, password string
}

func newAuthTestSuite(t *testing.T) *authTestSuite {
	var (
		username = "foo"
		password = "bar"
	)
	return &authTestSuite{
		username: username,
		password: password,
		InterceptorTestSuite: &grpc_testing.InterceptorTestSuite{
			TestService: &grpc_testing.TestPingService{T: t},
			ServerOpts: []grpc.ServerOption{
				grpc.StreamInterceptor(StreamServerInterceptor(username, password)),
				grpc.UnaryInterceptor(UnaryServerInterceptor(username, password)),
			},
		},
	}
}

func (s *authTestSuite) TestUnary_Passed() {
	cli := s.NewClient(
		grpc.WithUnaryInterceptor(UnaryClientInterceptor(s.username, s.password)),
	)
	_, err := cli.Ping(s.SimpleCtx(), ping)
	require.NoError(s.T(), err, "no error must occur")
}

func (s *authTestSuite) TestStream_Passed() {
	cli := s.NewClient(
		grpc.WithStreamInterceptor(StreamClientInterceptor(s.username, s.password)),
	)
	stream, err := cli.PingList(s.SimpleCtx(), ping)
	require.NoError(s.T(), err, "no error must occur")
	_, err = stream.Recv()
	require.NoError(s.T(), err, "no error must occur")
}

func (s *authTestSuite) TestUnary_Failed() {
	cli := s.NewClient(
		grpc.WithUnaryInterceptor(UnaryClientInterceptor(s.username, s.password+"1")),
	)
	_, err := cli.Ping(s.SimpleCtx(), ping)
	assert.Error(s.T(), err, "there must be an error")
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.Unauthenticated, st.Code(), "must be unauthenticated")
}

func (s *authTestSuite) TestStream_Faield() {
	cli := s.NewClient(
		grpc.WithStreamInterceptor(StreamClientInterceptor(s.username, s.password+"1")),
	)
	stream, err := cli.PingList(s.SimpleCtx(), ping)
	require.NoError(s.T(), err, "no error must occur")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	st, _ := status.FromError(err)
	assert.Equal(s.T(), codes.Unauthenticated, st.Code(), "must be unauthenticated")
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, newAuthTestSuite(t))
}
