<template >
    <div class="page-activate child-view">
        <div class="activate-body">
            <div class="activate-box">
                <img class=" m-auto block rotate-image" src="@/statics/images/icon/invalid.svg">
                <p class="text-24  text-center text-text-li mt-36">{{ error }}</p>
                <n-button v-if="btnText && source_url" class="w-full mt-36" @click="handleButton" :type="'primary'">{{ btnText }}</n-button>
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
import { useRoute  } from 'vue-router';

const route = useRoute()
const error = ref("")
const btnText = ref("")
const type = ref("register") // password, invalid
const source_url = ref("")

onMounted(()=>{
    // 来源
    let sourceUrl = decodeURIComponent(String(route.query.source_url || ''));
    try {
        sourceUrl = atob(sourceUrl)
    } catch (error) {}
    //
    route.query.type && (type.value = route.query.type + '')
    source_url.value = sourceUrl
    //
    if (type.value == 'invalid') {
        error.value = $t("链接已失效，请联系专属客服")
    }
    //
    if (type.value == 'register') {
        error.value = $t("链接已失效，请重新注册")
        btnText.value = $t("返回注册")
    }
    //
    if (type.value == 'password') {
        error.value = $t("链接已失效，请重新发起")
        btnText.value = $t("返回重置密码")
    }
})

const handleButton = () => {
    window.location.href = source_url.value;
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
</style>
