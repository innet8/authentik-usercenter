<template >
    <div class="page-activate child-view">
        <div class="activate-body">
            <div class="activate-box" v-if="showType==2">
                <h3 class="text-32 font-semibold text-center text-text-li">{{ $t('设置密码') }}</h3>
                <p class="text-22 text-center text-text-li mt-30">{{ $t('首次激活需要设置密码') }}</p>
                <div class="bg-[#F8F8F8] rounded px-16 py-12 mb-16 mt-16">
                    <p class=" text-text-tips text-14 "> {{ $t('您的登录密码长度必须至少是6个字符，并且至少包含2种不同类型字符') }}</p>
                </div>
                <transition name="login-mode">
                    <n-form ref="formRef" :rules="rules" label-placement="left" :show-require-mark="false"
                        :model="formData">
                        <n-form-item path="password">
                            <n-input type="password" v-model:value="formData.password" :placeholder="$t('请设置新密码')" :maxlength="24"
                                clearable>
                                <template #prefix>
                                    <n-icon :component="LockClosed" />
                                </template>
                            </n-input>
                        </n-form-item>
                        <n-button class="w-full" type="primary" :loading="loadIng" @click="handleSetPass">{{ $t("设置密码 ")}}</n-button>
                    </n-form>
                </transition>
            </div>
            <div class="activate-box" v-else-if="showType==3">
                <img class=" m-auto block" src="@/statics/images/icon/activate.svg">
                <p class="text-24  text-center text-text-li mt-36">{{ $t("账号已激活，可直接登录") }}</p>
                <n-button class="w-full mt-36" @click="handleButton(1)" :type="'primary'">{{ $t("返回登录") }}</n-button>
            </div>
            <div class="activate-box" v-else-if="showType==4">
                <img class="m-auto block " src="@/statics/images/icon/invalid.svg">
                <p class="text-24 text-center text-text-li mt-36">
                    {{ regType == 'web' ? error : $t("链接已失效，请联系专属客服")}}
                </p>
                <n-button v-if="error && regType == 'web'" class="w-full mt-36" @click="handleButton(2)" :type="'primary'">
                    {{ $t("返回注册") }}
                </n-button>
            </div>
            <div class="activate-box" v-else>
                <img class=" m-auto block rotate-image" src="@/statics/images/icon/loading-full.svg">
                <h3 class="text-32 font-semibold text-center text-text-li mt-40">{{ $t('激活账号中...') }}</h3>
                <p class="text-16 text-center text-text-li mt-16">{{ $t('账号激活中，请耐心等待，激活成功后页面自动刷新页面') }}</p>
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
import { useRoute  } from 'vue-router';
import { verifyRegisterEmail, setFirstPassword } from '@/api/modules/user';
import { useMessage } from "@/utils/messageAll"
import webTs from "@/utils/web"
import { LockClosed } from "@vicons/ionicons5"

const route = useRoute()
const message = useMessage()

// 来源
let sourceUrl = decodeURIComponent(String(route.query.source_url || ''));
try {
    sourceUrl = atob(sourceUrl)
} catch (error) {}
if (route.query.language) {
    sourceUrl = webTs.addParamToUrl(sourceUrl,'lang', route.query.language)
}
try {
    sourceUrl = webTs.delParamToUrl(sourceUrl,'auth_token')
} catch (error) {}

const error = ref("")
const regType = ref<String>(String(route.query.reg_type || webTs.getRequest(sourceUrl,'reg_type') || '') || "web")
const showType = ref(1)
const loadIng = ref<boolean>(false)
const formRef = ref()
const formData = ref({password: ""})
const rules = ref({
    password: {
        required: true,
        message: $t('请输入密码'),
        trigger: ['input', 'blur']
    }
})

const handleActivate = () => {
    verifyRegisterEmail({
        code: route.query.code,
        language: route.query.language,
        pwd_key: route.query.pwd_key || '',
        email: route.query.email || '',
    }).then(({code, data, msg}) => {
        message.success($t("激活成功！"))
        if (data.pwd_key) {
            showType.value = 2;
        } else {
            setTimeout(()=>{
                window.location.href = webTs.addParamToUrl(sourceUrl,'pageType','');
            },2000)
        }
    }).catch(res => {
        if (res.code == 2) {
            showType.value = 3;
        } else {
            showType.value = 4;
            error.value = $t(res.msg);
        }
    }).finally(() => {

    })
}

onMounted(()=>{
    if(route.query.code){
        handleActivate()
    }
})

const handleButton = (type=1) => {
    window.location.href = type == 2 ? webTs.addParamToUrl(sourceUrl,'pageType','reg') : webTs.addParamToUrl(sourceUrl,'pageType','');
}

const handleSetPass = () => {
    formRef.value.validate().then(() => {
        loadIng.value = true
        setFirstPassword({
            pwd_key: route.query.pwd_key || '',
            password: formData.value.password,
        }).then(({code, data, msg}) => {
            message.success($t("设置成功！"))
            window.location.href = webTs.addParamToUrl(sourceUrl,'pageType','');
        }).catch(res => {
            message.error(res.msg)
        }).finally(() => {
            loadIng.value = false
        })
    }).catch(() => {

    })
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
