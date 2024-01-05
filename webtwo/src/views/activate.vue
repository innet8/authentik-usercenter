<template >
    <div class="page-activate child-view">
        <div class="activate-body">
            <div class="activate-box">
                <img class=" m-auto block rotate-image" src="@/statics/images/icon/loading-full 1.svg">
                    <h3 class="text-32 font-semibold text-center text-text-li mt-40">{{ $t('激活账号中...') }}</h3>
                    <p class="text-16 text-center text-text-li mt-16">{{ $t('账号激活中，请耐心等待，激活成功后页面自动刷新页面') }}</p>
            </div>
        </div>
    </div>
</template>
<script setup lang="ts">
import { useRoute ,useRouter } from 'vue-router';
import { verifyRegisterEmail } from '@/api/modules/user';
import { useMessage } from "@/utils/messageAll"
const route = useRoute()
const router = useRouter()
const message = useMessage()

const handleActivate = () => {

    verifyRegisterEmail({
        code: route.query.code,
        language: route.query.language,
    }).then(({ data, msg }) => {
        message.success($t("激活成功！"))
        setTimeout(()=>{
            router.push({name:'login'})
        },3000)
    })
        .catch(res => {
            message.error($t(res.msg))
        }).finally(() => {
   
        })

}
onMounted(()=>{
    if(route.query.code){
        handleActivate()
    }
})

</script>
<style scoped>
.page-activate {
    @apply bg-bg-login flex items-center;
}
.activate-body {
    @apply flex items-center flex-col max-h-full overflow-hidden py-5 w-full;
}

.activate-box {
    @apply bg-bg-login-box shadow-login-box-Shadow rounded w-368 p-40 relative;
}

.rotate-image {
  animation: rotate 2s linear infinite; /* 设置动画名称、持续时间、速度和无限循环 */
}

@keyframes rotate {
  0% {
    transform: rotate(0deg); /* 设置初始位置，此处为 0 度 */
  }
  100% {
    transform: rotate(360deg); /* 设置结束位置，此处为 360 度 */
  }
}

</style>