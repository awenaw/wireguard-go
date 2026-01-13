.PHONY: build run clean

# 输出的二进制文件名
BINARY_NAME=wireguard-go

# 默认构建
build:
	@echo "正在编译 $(BINARY_NAME)..."
	go build -o $(BINARY_NAME)

# 编译并运行服务端 (需要 sudo 密码)
run: build
	@echo "正在启动服务端..."
	sudo ./wg_config/start_server.sh

# 清理
clean:
	@echo "正在清理..."
	rm -f $(BINARY_NAME)
