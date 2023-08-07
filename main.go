package main

import (
	"github.com/caarlos0/env"
	profileProtocol "github.com/distuurbia/profile/protocol/profile"
	balanceProtocol "github.com/distuurbia/balance/protocol/balance"
	"github.com/distuurbia/tradeAPI/internal/config"
	"github.com/distuurbia/tradeAPI/internal/handler"
	"github.com/distuurbia/tradeAPI/internal/repository"
	"github.com/distuurbia/tradeAPI/internal/service"
	customMiddleware "github.com/distuurbia/tradeAPI/internal/middleware"
	"github.com/go-playground/validator"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createProfileClientConnection() (*grpc.ClientConn, error) {
	conn, err := grpc.Dial("localhost:8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func createBalanceClientConnection() (*grpc.ClientConn, error) {
	conn, err := grpc.Dial("localhost:8082", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func main(){
	var cfg config.Config
	if err := env.Parse(&cfg); err != nil {
		logrus.Errorf("main -> %v", err)
	}

	validate := validator.New()

	profileConn, err := createProfileClientConnection()
	if err != nil {
		logrus.Errorf("main -> : %v", err)
	}
	defer func() {
		errConnClose := profileConn.Close()
		if errConnClose != nil {
			logrus.Fatalf("main -> : %v", errConnClose)
		}
	}()

	balanceConn, err := createBalanceClientConnection()
	if err != nil {
		logrus.Errorf("main -> : %v", err)
	}
	defer func() {
		errConnClose := balanceConn.Close()
		if errConnClose != nil {
			logrus.Fatalf("main -> : %v", errConnClose)
		}
	}()

	profileClient := profileProtocol.NewProfileServiceClient(profileConn)
	balanceClient := balanceProtocol.NewBalanceServiceClient(balanceConn)

	profileRps := repository.NewProfileClientRepository(profileClient)
	balanceRps := repository.NewBalanceClientRepository(balanceClient)

	profileSrvc := service.NewProfileService(profileRps, &cfg)
	balanceSrvc := service.NewBalanceService(balanceRps)

	h := handler.NewTradeApiHandler(profileSrvc, balanceSrvc, validate)

	cm := customMiddleware.NewCustomMiddleware(*profileSrvc)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/signUp", h.SignUp)
	e.POST("/login", h.Login)
	e.POST("/refresh", h.Refresh)
	e.DELETE("/deleteProfile", h.DeleteProfile, cm.JWTMiddleware)

	e.POST("/deposit", h.AddBalanceChange, cm.JWTMiddleware)
	e.POST("/withdraw", h.AddBalanceChange, cm.JWTMiddleware)
	e.GET("/getBalance", h.GetBalance, cm.JWTMiddleware)


	e.Logger.Fatal(e.Start(":8080"))

}