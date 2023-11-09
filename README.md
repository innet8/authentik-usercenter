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
```


## 接入文档

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

