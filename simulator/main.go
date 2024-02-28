package main

import (
	"fmt"
	"github.com/dajiangai/openwhatsapp/apps/messenger"
)

func main() {
	fmt.Println("请输入国家码:[hk]")

	var country string
	_, err := fmt.Scanln(&country)
	if err != nil {
		return
	}

	fmt.Println("请输入手机号:")

	var phoneNumber string
	_, err = fmt.Scanln(&phoneNumber)
	if err != nil {
		return
	}

	app := messenger.NewMessenger(phoneNumber, country, "")
	err = app.Run()

	if err != nil {
		fmt.Printf("错误:%v\n", err.Error())
	} else {
		fmt.Println("成功")
	}
	return
}
