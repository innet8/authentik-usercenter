import { $t } from "@/lang/index"
import Layout from '@/layout/index.vue'
import Login from '@/views/login.vue'
import Register from '@/views/register.vue'
import Success from '@/views/success.vue'

export const routes = [
    {
        name: "login",
        path: "/page/login",
        meta: { title: $t('登陆'), login: false },
        component: Login
    },
    {
        name: "register",
        path: "/page/register",
        meta: { title: $t('注册'), login: false },
        component: Register
    },
    {
        name: "success",
        path: "/page/success",
        meta: { title: $t('成功'), login: false },
        component: Success
    }
]
