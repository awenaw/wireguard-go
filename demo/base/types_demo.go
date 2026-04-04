package main

import (
	"fmt"
	"math"
)

// 1. 基础类型重定义 (Type Definition)
type Celsius float64
type Fahrenheit float64

// 2. 类型别名 (Type Alias - 主要用于重构，Go 1.9+)
type Seconds = int

// 3. 结构体类型 (Struct Type)
type User struct {
	ID   int
	Name string
}

// 6. 为结构体添加值接收者方法 (Value Receiver)
// 适用于不需要修改结构体状态的场景
func (u User) Greet() {
	fmt.Printf("你好，我是 %s (ID: %d)\n", u.Name, u.ID)
}

// 7. 为结构体添加指针接收者方法 (Pointer Receiver)
// 适用于需要修改结构体内容，或为了避免大型结构体复制的性能损耗
func (u *User) UpdateName(newName string) {
	u.Name = newName
	fmt.Printf("名称已更新为: %s\n", u.Name)
}

// 4. 接口类型 (Interface Type)
type Shaper interface {
	Area() float64
}

type Circle struct {
	Radius float64
}

// Circle 实现了 Shaper 接口（隐式实现）
func (c Circle) Area() float64 {
	return math.Pi * c.Radius * c.Radius
}

// 5. 为自定义类型添加方法
func (c Celsius) ToFahrenheit() Fahrenheit {
	return Fahrenheit(c*9/5 + 32)
}

func main() {
	// 使用基础自定义类型
	var temp Celsius = 25.5
	fmt.Printf("当前温度: %.2f°C, 转换为华氏度: %.2f°F\n", temp, temp.ToFahrenheit())

	// 使用类型别名
	var s Seconds = 60
	fmt.Printf("持续时间: %d 秒\n", s)

	// 使用结构体
	u := User{ID: 1, Name: "Antigravity"}
	fmt.Printf("用户信息: %+v\n", u)

	// 调用 User 的方法
	u.Greet()              // 调用值接收者方法
	u.UpdateName("Antigravity-v2") // 调用指针接收者方法
	u.Greet()              // 验证修改成功

	// 使用接口和多态
	var shape Shaper
	c := Circle{Radius: 5}
	shape = c
	fmt.Printf("圆形的面积: %.2f\n", shape.Area())

	// 类型断言与检查
	if v, ok := shape.(Circle); ok {
		fmt.Printf("成功断言为 Circle, 半径为: %.2f\n", v.Radius)
	}
}
