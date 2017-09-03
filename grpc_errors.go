package backend_utils

import (
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
)

/*
 * gRPC error codes that are mapped to HTTP errors by grpc-gateway
 * All the common error codes are exported from here
 * as variables to avoid common function calls.
 *
 * 	grpc Error code		 |	Http error status
 * --------------------------------------------------------------------
 *	codes.OK		 |	http.StatusOK
 *	codes.Canceled           |	http.StatusRequestTimeout
 *	codes.Unknown            |	http.StatusInternalServerError
 *	codes.InvalidArgument    |	http.StatusBadRequest
 *	codes.DeadlineExceeded   |	http.StatusRequestTimeout
 *	codes.NotFound           |	http.StatusNotFound
 *	codes.AlreadyExists      |	http.StatusConflict
 *	codes.PermissionDenied   |	http.StatusForbidden
 *	codes.Unauthenticated    |	http.StatusUnauthorized
 *	codes.ResourceExhausted  |	http.StatusForbidden
 *	codes.FailedPrecondition |	http.StatusPreconditionFailed
 *	codes.Aborted		 |	http.StatusConflict
 *	codes.OutOfRange	 |	http.StatusBadRequest
 *	codes.Unimplemented	 |	http.StatusNotImplemented
 *	codes.Internal		 |	http.StatusInternalServerError
 *	codes.Unavailable	 |	http.StatusServiceUnavailable
 *	codes.DataLoss		 |	http.StatusInternalServerError
 *
 * 	Any other code will be defaulted to http.StatusInternalServerError
 */

// Not all of the above errors are implemented. Add them as and when required.
var (
	ErrUnknown = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.Unknown, msg, args...)
	}

	ErrInvalidArg = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.InvalidArgument, msg, args...)
	}

	ErrNotFound = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.NotFound, msg, args...)
	}

	ErrAlreadyExists = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.AlreadyExists, msg, args...)
	}

	ErrResourceExhausted = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.ResourceExhausted, msg, args...)
	}

	ErrPermissionDenied = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.PermissionDenied, msg, args...)
	}

	ErrUnauthenticated = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.Unauthenticated, msg, args...)
	}

	ErrInternal = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.Internal, msg, args...)
	}

	ErrUnimplemented = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.Unimplemented, msg, args...)
	}

	ErrUnavailable = func(msg string, args... interface{}) *status.Status {
		return status.Newf(codes.Unavailable, msg, args...)
	}
)
