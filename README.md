<p align="center">
    <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" height="150" alt="authentik logo">
</p>


## 部署

#### 1.执行本地打包容器指令并运行容器
```
make docker
```

#### 2.设置管理账号默认密码
```
1. 访问 http://localhost:9000/if/flow/initial-setup/
2. 设置完成可前往登录 http://localhost:9000/  账号: akadmin
```

#### 3.env环境讲解
```
PG_PASS=                  #数据库密码
AUTHENTIK_SECRET_KEY=     #项目key
COMPOSE_PORT_HTTP=9000    #项目端口

JWT_SECRET_KEY=			  # token密钥（填写随机字符串）
JWT_ALGORITHM=HS256		  # 加密方式

API_TOKEN=                # API密钥（填写随机字符串）
```


## 接入文档

#### 登录接口

地址 http://127.0.0.1:9000/api/v3/core/users/login/

请求方式 POST

请求参数

| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| username | String | 账户 |
| password | String | 密码 |

返回参数
| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| data | String | 返回数据 |
| msg | String | 请求结果描述 |
| code | Number | 请求结果 0-失败 1-成功 |

请求成功示例
```
{
	"data": {
		"token": "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjMlZ5WDNCcklqbzFNeXdpZFhObGNtNWhiV1VpT2lKMFpYTjBPVGtpTENKemIzVnlZMlVpT2lKd2QyWWlMQ0psZUhBaU9qRTJPVGsyTURFMk1qaDkuRmt2Mi1hUkZ4M3B6Z2RlcWpRbm9kQXhiM2lEbURRbVV0cDJnblBwU2pYWQ=="
	},
	"msg": "请求成功",
	"code": 1
}
```

#### 注册接口

地址 http://127.0.0.1:9000/api/v3/core/users/register/

请求方式 POST

请求参数

| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| username | String | 账户 |
| password | String | 密码 |
| source | String | 来源 |

返回参数
| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| data | String | 返回数据 |
| msg | String | 请求结果描述 |
| code | Number | 请求结果 0-失败 1-成功 |

请求成功示例
```
{
	"data": {
		"username": "test999",
		"user_uid": "5d43911708dc996f0466df4383ca6655f5afb761d38a0a380ef4451297708358",
		"user_pk": 54,
		"source": "pwf"
	},
	"msg": "请求成功",
	"code": 1
}
```

#### 解析Token获取用户信息接口

地址 http://127.0.0.1:9000/api/v3/core/users/get_info/

请求方式 POST

请求参数

| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| token | String | 登录返回的token |

返回参数
| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| data | String | 返回数据 |
| msg | String | 请求结果描述 |
| code | Number | 请求结果 0-失败 1-成功 |

请求成功示例
```
{
	"data": {
		"user_pk": 53,
		"username": "test99",
		"source": "pwf",
		"exp": 1699597936
	},
	"msg": "请求成功",
	"code": 1
}
```

#### 获取用户列表

地址 http://127.0.0.1:9000/api/v3/core/users/get_list/

请求方式 POST

请求头部
| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| APITOKEN | String | settings.py 的 API_TOKEN |

请求参数

无

返回参数
| 参数名 | 类型 | 描述 |
|--------|--------|--------|
| data | String | 返回数据 |
| msg | String | 请求结果描述 |
| code | Number | 请求结果 0-失败 1-成功 |

请求成功示例
```
{
	"data": [
		{
			"username": "yh9034w85h"
		},
        ...
	],
	"msg": "请求成功",
	"code": 1
}
```

#### 登录页

地址 http://127.0.0.1:9000/page/login?language=zh

路由参数

| 参数名 | 默认值 | 描述 |
|--------|--------|--------|
| language | zh | 显示语言 - en、zh、zh-cht、fr、id、ja、ko |
| source | sys-web | 来源 |
| callback | /page/success | 登录成功后的回调地址,会附带ak-token参数在上面,可通过ak-token去请求接口 [/api/v3/core/users/getInfo/] 获取用户信息|
| title | 登录 | 登录页的标题 |
| subtitle | 输入您的凭证以访问您的帐户 | 标题下方的描述 |
| switch | true | 打开切换注册的按钮 |
| color |  | 字体色 - 透明色：transparent 白色：white |
| bgColor | white | 背景色 - 透明色：transparent 白色：white |
| shadow |  | 阴影 - 不显示：none |
| btncolor |  | 按钮色 - default、tertiary、primary、info、success、warning 和 error |
| theme | default | 主题 |

#### 注册页

地址 http://127.0.0.1:9000/page/register?language=zh

路由参数

| 参数名 | 默认值 | 描述 |
|--------|--------|--------|
| language | zh | 显示语言 - en、zh、zh-cht、fr、id、ja、ko |
| source | sys-web | 来源 |
| callback | /page/login | 注册成功后的回调地址 |
| title | 注册 | 注册页的标题 |
| subtitle | 输入您的信息以创建帐户 | 标题下方的描述 |
| switch | true | 打开切换登录页的按钮 |
| color |  | 字体色 - 透明色：transparent 白色：white |
| bgColor | white | 背景色 - 透明色：transparent 白色：white |
| shadow |  | 阴影 - 不显示：none |
| btncolor |  | 按钮色 - default、tertiary、primary、info、success、warning 和 error |
| theme | default | 主题 |

