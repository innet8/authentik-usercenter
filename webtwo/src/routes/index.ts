import { createRouter, createWebHistory } from 'vue-router'
import { ref } from "vue";
import { UserStore } from "@/store/user"
import { GlobalStore } from "@/store"
import { $t } from "@/lang/index"

export const loadingBarApiRef = ref(null)

export default function createDemoRouter(app, routes) {
    const router = createRouter({
        history: createWebHistory(),
        routes
    })

    router.beforeEach(function (to, from, next) {
        //
        document.cookie = "authentik_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        document.cookie = "authentik_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        //
        const userStore = UserStore();
        if(to.query.token){
            userStore.setToken(to.query.token)
        }
        //
        if(to.query.language){
            GlobalStore().setLanguage(to.query.language)
        }
        //
        // 需要登录
        // if(to.name !== 'login' && to.meta?.login !== false && !userStore.info?.token){
        //     router.replace({name:'login'})
        //     return;
        // }
        // 已经登录
        // if(to.name == 'login' && userStore.info?.token){
        //     router.replace({name:'/'})
        //     return;
        // }
        // 进度
        // if (!from || to.path !== from.path) {
        //     if (loadingBarApiRef.value) {
        //         loadingBarApiRef.value.start()
        //     }
        // }
        //
        next()
    })

    router.afterEach(function (to, from) {
        if(to?.meta?.title){
            document.title = $t(to.meta.title + '')
        }
        GlobalStore().setBaseRoute(to.params?.catchAll || '')
        if (!from || to.path !== from.path) {
            if (loadingBarApiRef.value) {
                loadingBarApiRef.value.finish()
            }
        }
    })

    return router
}
