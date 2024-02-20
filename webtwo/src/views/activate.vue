<template >
    <div class="page-activate child-view">
        <div class="activate-body">
            <div class="activate-box" v-if="!error">
                <img class=" m-auto block rotate-image" src="@/statics/images/icon/loading-full.svg">
                <h3 class="text-32 font-semibold text-center text-text-li mt-40">{{ $t('激活账号中...') }}</h3>
                <p class="text-16 text-center text-text-li mt-16">{{ $t('账号激活中，请耐心等待，激活成功后页面自动刷新页面') }}</p>
            </div>
            <div v-else class="activate-box">
                <img class="m-auto block " src="@/statics/images/icon/invalid.svg">
                <p class="text-24  text-center text-text-li mt-36">{{ error }}</p>
                <n-button v-if="callback" class="w-full mt-36" @click="handleButton" :type="'primary'">{{ $t("返回注册") }}</n-button>
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
import { useRoute  } from 'vue-router';
import { verifyRegisterEmail } from '@/api/modules/user';
import { useMessage } from "@/utils/messageAll"

const route = useRoute()
const message = useMessage()
const error = ref("")
const callback = ref("")

// 来源
let sourceUrl = decodeURIComponent(String(route.query.sourceUrl || ''));
try {
    sourceUrl = atob(sourceUrl)
} catch (error) {}

const handleActivate = () => {
    verifyRegisterEmail({
        code: route.query.code,
        language: route.query.language,
    }).then(({ data, msg }) => {
        message.success($t("激活成功！"))
        setTimeout(()=>{
            window.location.href = sourceUrl;
        },3000)
    }).catch(res => {
        error.value = $t(res.msg);
    }).finally(() => {

    })
}

onMounted(()=>{
    route.query.callback && (callback.value = route.query.callback + '')
    if(route.query.code){
        handleActivate()
    }
})

const handleButton = () => {
    window.location.href = callback.value;
}

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
