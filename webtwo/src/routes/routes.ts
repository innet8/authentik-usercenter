import Login from '@/views/login.vue'
import Register from '@/views/register.vue'
import Activate from '@/views/activate.vue'
import ResetPassword from '@/views/resetPassword.vue'
import Success from '@/views/success.vue'
import Invalid from '@/views/invalid.vue'


export const routes = [
    {
        name: "login",
        path: "/page/login",
        meta: { title: '登录', login: false },
        component: Login
    },
    {
        name: "register",
        path: "/page/register",
        meta: { title: '注册', login: false },
        component: Register
    },
    {
        name: "activate",
        path: "/page/activate",
        meta: { title: '激活', login: false },
        component: Activate
    },
    {
        name: "resetPassword",
        path: "/page/resetPassword",
        meta: { title: '重置密码', login: false },
        component: ResetPassword
    },
    {
        name: "success",
        path: "/page/success",
        meta: { title: '成功', login: false },
        component: Success
    },
    {
        name: "invalid",
        path: "/page/invalid",
        meta: { title: '链接失效页面', login: false },
        component: Invalid
    }
]
