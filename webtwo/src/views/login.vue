<template>
    <div class="page-login child-view" :style="customStyles">
        <div class="login-body">
            <div class="login-box" :style="customStyles">
                <h2 class="login-title">
                    <span>{{ config.title || formTitle }}</span>
                </h2>
                <!-- <p class="login-subtitle">
                    {{ config.subtitle || loginType == 'reg' ? $t("输入您的信息以创建帐户") : $t("输入您的凭证以访问您的帐户") }}
                </p> -->
                <transition name="login-mode">
                    <n-form ref="formRef" :rules="rules" label-placement="top" :show-require-mark="false" :model="formData">
                        <div v-if="loginMode == 'access'" class="login-access">
                            <div class="bg-[#F8F8F8] rounded px-16 py-12 mb-24" v-if="loginType == 'forgot'">
                                <p class=" text-text-tips text-14 "> {{ $t('输入与您的账号关联的电子邮件地址，我们将向您发送一个链接以重置您的密码。') }}
                                </p>
                            </div>
                            <n-form-item :label="$t('邮箱')" path="email"
                                v-if="loginType == 'reg' || loginType == 'login' || loginType == 'forgot'">
                                <n-input v-model:value="formData.email" @blur="onBlur" :placeholder="$t('请输入用户账号')"
                                    clearable>
                                    <template #prefix>
                                        <n-icon :component="Mail" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-form-item :label="$t('密码')" path="password"
                                v-if="loginType == 'reg' || loginType == 'login'">
                                <n-input type="password" v-model:value="formData.password" @blur="onBlur"
                                    :placeholder="$t('请输入登录密码')" clearable>
                                    <template #prefix>
                                        <n-icon :component="LockClosed" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-form-item :label="$t('验证码')" path="code" v-if="codeNeed">
                                <n-input class="code-load-input" v-model:value="code" :placeholder="$t('输入图形验证码')"
                                    clearable>
                                    <template #prefix>
                                        <n-icon :component="CheckmarkCircleOutline" />
                                    </template>
                                    <template #suffix>
                                        <div class="login-code-end" @click="refreshCode">
                                            <div v-if="codeLoad > 0" class="code-load">
                                                <Loading />
                                            </div>
                                            <span v-else-if="codeUrl === 'error'" class="code-error">{{ $t("加载失败") }}</span>
                                            <img v-else :src="codeUrl" />
                                        </div>
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-form-item :label="$t('确认密码')" path="confirmPassword" v-if="loginType == 'reg'">
                                <n-input type="password" v-model:value="formData.confirmPassword"
                                    :placeholder="$t('输入确认密码')" clearable>
                                    <template #prefix>
                                        <n-icon :component="LockClosed" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <div class="" v-if="loginType == 'regSuccess'">
                                <p class="text-text-li text-16 font-normal">{{ $t('我们发送邮件至') }} <span
                                        class=" text-[#0C9189]">{{ formData.email }}</span>
                                    {{ $t('请点击我们刚刚发送到您收件箱的链接来确认您的电子邮件地址') }}</p>
                            </div>
                            <div class="" v-if="loginType == 'secure'">
                                <p class="text-text-li text-16 font-normal">{{ $t('平台已对用户账号进行了全面升级，请点击我们刚刚发送到您收件箱') }} <span
                                        class=" text-[#0C9189]">（{{ formData.email }}）</span>
                                    {{ $t('的链接来确认您的电子邮件地址！') }}</p>
                            </div>
                            <div class="login-switch" v-if="config.switch !== 'false'">
                                <template v-if="loginType == 'login'">
                                    <div class="flex items-center justify-between">
                                        <p>
                                            {{ $t("还没有账号？") }}
                                            <a href="javascript:void(0)" @click="changeLoginType('reg')"> {{ $t("注册账号")
                                            }}</a>
                                        </p>
                                        <p class=" text-center"><a href="javascript:void(0)"
                                                @click="changeLoginType('forgot')"> {{ $t("忘记密码") }}</a></p>
                                    </div>

                                </template>

                                <template v-if="loginType == 'reg'">
                                    <div class="flex items-center justify-between">
                                        <p>
                                            {{ $t("已经有账号？") }}
                                            <a href="javascript:void(0)" @click="changeLoginType('login')"> {{ $t("登录账号")
                                            }}</a>
                                        </p>

                                    </div>

                                </template>

                                <template v-if="loginType == 'forgot'">
                                    <a href="javascript:void(0)" @click="changeLoginType('login')"> {{ $t("返回登录") }}</a>
                                </template>
                            </div>
                            <n-button v-if="loginType == 'login'" :loading="loadIng" @click="handleLogin"
                                :type="config.btncolor">{{ $t("登录") }}</n-button>
                            <n-button v-if="loginType == 'reg'" type="primary" :loading="loadIng" @click="handleReg">{{
                                $t("注册") }}</n-button>
                            <n-button v-if="loginType == 'regSuccess'" type="primary" :disabled="resendCTime > 0"
                                :loading="loadIng" @click="handleResend">{{ resendCTime > 0 ? $t("重新发送") +
                                    `(${resendCTime}s)`
                                    : $t("重新发送验证邮件") }}</n-button>
                            <n-button v-if="loginType == 'secure'" type="primary" :disabled="resetTime > 0"
                                :loading="loadIng" @click="handleReset">{{ resetTime > 0 ? $t("重新发送") +
                                    `(${resetTime}s)`
                                    : $t("重新发送验证邮件") }}</n-button>
                            <n-button v-if="loginType == 'forgot'" type="primary" :loading="loadIng"
                                :disabled="resetTime > 0" @click="handleReset">
                                {{ resetTime > 0 ? $t("重新发送") + `(${resetTime}s)` : $t("请求重置密码") }}
                            </n-button>
                            <template v-if="loginType == 'regSuccess'">
                                <p class="flex justify-center mt-16 text-14 text-text-tips">
                                    {{ $t("已验证完邮箱或更换邮箱？") }}
                                    <a class=" text-primary-color no-underline" href="javascript:void(0)"
                                        @click="changeLoginType('login')"> {{ $t("登录账号") }}</a>
                                </p>
                            </template>
                            <div class="flex justify-center mt-32"
                                v-if="loginType == 'forgot' || loginType == 'reg' || loginType == 'login'">
                                <n-dropdown trigger="click" :options="options" @select="setLanguage">
                                    <span class="flex items-center cursor-pointer text-14 gap-1 text-text-li"><img
                                            src="../statics/images/icon/global.svg">{{ languageLabel }} <n-icon
                                            color="#9CA3AF" size="12" :component="ChevronDownOutline" /></span>
                                </n-dropdown>
                            </div>
                        </div>
                    </n-form>
                </transition>
            </div>
        </div>
    </div>
</template>

<script lang="ts" setup>
import { ref, computed } from "vue"
import { userLogin, userReg, resend, needCode, resetPassword } from "@/api/modules/user"
import { FormItemRule, useDialog } from "naive-ui"
import { useMessage } from "@/utils/messageAll"
import { UserStore } from "@/store/user"
import { useRoute } from "vue-router"
import { Mail, LockClosed, CheckmarkCircleOutline, ChevronDownOutline } from "@vicons/ionicons5"
import webTs from "@/utils/web"

const message = useMessage()
const route = useRoute()
const loadIng = ref<boolean>(false)
const code = ref("")
const codeUrl = ref("")
const codeLoad = ref(0)
const userState = UserStore()
const dialog = useDialog()
const loginMode = ref("access") //qrcode
const codeNeed = ref(false)
const resendCTime = ref(0)
const resetTime = ref(0)
const loginType = ref<String>("login")
const formRef = ref(null)
const formData = ref({
    email: "",
    password: "",
    confirmPassword: "",
    invite: "",
})

const options = ref([
    {
        label: '繁体',
        key: 'zh-CHT',
    },
    {
        label: 'English',
        key: 'en',
    },
]
)
const languageLabel = computed(() => {
    let result = '繁体'
    options.value.map((item) => {
        if (item.key == route.query.language) { result = item.label }
    })
    return result
})

// 路由参数配置
const config = ref({
    language: route.query.language || 'zh-CHT',         //  显示语言 - en、zh、zh-cht、fr、id、ja、ko
    source: route.query.source || '',              //  来源
    sourceUrl: route.query.sourceUrl || '',              //  来源URL
    callback: route.query.callback || '',          //  登录成功后浏览器去往的地址
    title: route.query.title || '',                //  标题
    subtitle: route.query.subtitle || '',          //  标题下方的描述
    switch: route.query.switch || 'true',           //  打开切换注册的按钮
    color: route.query.color || '',                //  字体色 - 透明色：transparent 白色：white
    bgcolor: route.query.bgColor || 'white',       //  背景色 - 透明色：transparent 白色：white
    shadow: route.query.shadow || '',              //  阴影 - 不显示：none
    btncolor: route.query.btnColor || 'primary',   //  按钮色 - default、tertiary、primary、info、success、warning 和 error
    theme: route.query.theme || 'default',       //  主题
})

// 样式
const customStyles = ref({
    color: config.value.color,
    backgroundColor: config.value.bgcolor,
    boxShadow: config.value.shadow,
})

const rules = ref({
    email: {
        required: true,
        validator(rule: FormItemRule, value: string) {
            if (!value) {
                return new Error($t('请输入账号'))
            }
            // else if (!utils.isEmail(value)) {
            //     return new Error($t('请输入正确的邮箱'))
            // }
            return true
        },
        trigger: ['input', 'blur']
    },
    password: {
        required: true,
        message: $t('请输入密码'),
        trigger: ['input', 'blur']
    },
    confirmPassword: {
        required: true,
        validator(rule: FormItemRule, value: string) {
            if (!value) {
                return new Error($t('请输入确认密码'))
            } else if (value != formData.value.password) {
                return new Error($t('两次密码输入不一致'))
            }
            return true
        },
        trigger: ['input', 'blur'],
    },
})

const formTitle = computed(() => {
    let result = $t('登录')
    if (loginType.value == 'reg') {
        result = $t('注册')
    }
    if (loginType.value == 'regSuccess') {
        result = $t('请确认您的邮箱地址')
    }
    if (loginType.value == 'forgot') {
        result = $t('忘记密码')
    }
    if (loginType.value == 'secure') {
        result = $t('账号安全升级')
    }
    return result
})

const setLanguage = (e) => {
    dialog.info({
        title: $t('提示'),
        content: $t('切换语言需要刷新后生效，是否确定刷新?'),
        positiveText: $t('确定'),
        negativeText: $t('取消'),
        onPositiveClick: () => {
            let url = window.location.href;
            let urlObj = new URL(url);
            urlObj.searchParams.set('language', e);
            let newUrl = urlObj.href;
            window.location.href = newUrl;
        },
        onNegativeClick: () => {

        }
    })
}

// 登录
const handleLogin = () => {
    let callback = config.value.callback;
    formRef.value?.validate((errors) => {
        if (errors) {
            return
        }
        loadIng.value = true
        userLogin({
            email: formData.value.email,
            username: formData.value.email,
            password: formData.value.password,
            pic_code: code.value,
            source_url: config.value.sourceUrl || '',
        }).then(({ data, msg }) => {
            userState.info = data
            if (callback) {
                callback = callback.indexOf("?") == -1 ? callback + "?ak-token=" : callback + "&ak-token="
                parent.window.location.href = callback + data.token
            } else {
                parent.window.location.href = parent.window.location.origin + `/page/success?language=${config.value.language}&ak-token=${data.token}`
            }
        })
            .catch(res => {
                loadIng.value = false
                if (res.data == "needcode") {
                    onBlur()
                }
                if(res.code!='10'){
                    message.error($t(res.msg))
                }
                if (res.code == "10") {
                    loginType.value = 'secure'
                    handleReset();
                }
            })
    }).catch(_ => { })
}

// 注册
const handleReg = () => {
    formRef.value?.validate((errors) => {
        if (errors) {
            return
        }
        loadIng.value = true
        userReg({
            username: formData.value.email,
            password: formData.value.password,
            source: (config.value.source + '') || 'sys-web',
            source_url: config.value.sourceUrl || '',
        }).then(({ data, msg }) => {
            message.success($t("注册成功"))
            loginType.value = "regSuccess"
            resendCTime.value = 120
            let times = setInterval(() => {
                resendCTime.value--;
                if (resendCTime.value <= 0) {
                    clearInterval(times);
                }
            }, 1000);

        })
            .catch(res => {
                message.error($t(res.msg))
            }).finally(() => {
                loadIng.value = false
            })
    }).catch(_ => { })
}

// 重新发送
const handleResend = () => {
    if (resendCTime.value > 0) {
        return;
    }
    loadIng.value = true
    resend({
        username: formData.value.email,
        language: route.query.language,
    }).then(({ data, msg }) => {
        message.success($t("重新发送成功！"))
        resendCTime.value = 120
        let times = setInterval(() => {
            resendCTime.value--;
            if (resendCTime.value <= 0) {
                clearInterval(times);
            }
        }, 1000);
    })
        .catch(res => {
            message.error($t(res.msg))
        }).finally(() => {
            loadIng.value = false
        })

}

// 找回密码
const handleReset = () => {
    loadIng.value = true
    resetPassword({
        step: 1,
        username: formData.value.email,
        source_url: config.value.sourceUrl || '',
    }).then(({ data, msg }) => {
        message.success($t("发送成功！"))
        resetTime.value = 120
        let times = setInterval(() => {
            resetTime.value--;
            if (resetTime.value <= 0) {
                clearInterval(times);
            }
        }, 1000);
    })
        .catch(res => {
            message.error($t(res.msg))
        }).finally(() => {
            loadIng.value = false
        })

}

// 变更登录类型
const changeLoginType = (e) => {
    loginType.value = e

}

// 判断要不要验证码
const onBlur = () => {
    if (loginType.value != 'login') return
    const upData = {
        username: formData.value.email,
    }
    needCode(upData)
        .then(({ data }) => {
            if (data == 'y') {
                codeNeed.value = true
                codeUrl.value = webTs.apiUrl(`/api/v3/core/users/picCode/?username=${formData.value.email}`)
            }
        })
}

// 刷新验证码
const refreshCode = () => {
    codeUrl.value = webTs.apiUrl(`/api/v3/core/users/picCode/?username=${formData.value.email}&_='` + Math.random())
}
</script>

<style lang="less" scoped>
.page-login {
    @apply bg-bg-login flex items-center;

    .login-body {
        @apply flex items-center flex-col max-h-full overflow-hidden py-5 w-full;

        .login-logo {
            @apply block w-84 h-84 bg-logo mb-36;
        }

        .login-box {
            @apply bg-bg-login-box shadow-login-box-Shadow rounded w-448 relative;
            max-width: 100%;

            .login-mode-switch {
                @apply absolute top-1 right-1 z-10 rounded-lg overflow-hidden;

                .login-mode-switch-box {
                    @apply w-80 h-80 cursor-pointer overflow-hidden bg-primary-color-80;
                    transition: background-color 0.3s;
                    transform: translate(40px, -40px) rotate(45deg);

                    &:hover {
                        @apply bg-primary-color;
                    }

                    .login-mode-switch-icon {
                        @apply absolute text-32 w-50 h-50 bottom-negative-20 left-4 flex items-start justify-start text-white;
                        transform: rotate(-45deg);

                        svg {
                            @apply w-30 h-30 ml-26 mt-8;
                        }
                    }
                }
            }

            .login-title {
                @apply text-30 font-semibold text-center mt-40;
            }

            .login-subtitle {
                @apply text-14 text-text-tips text-center mt-12 px-12;
            }

            .login-qrcode {
                @apply flex items-center justify-center m-auto my-50;
            }

            .login-access {
                @apply mt-32 mx-40 mb-40;

                .n-input {
                    transition: all 0s;
                }

                :deep(.code-load-input) {
                    .n-input-wrapper {
                        @apply pr-0;
                    }

                    .login-code-end {
                        @apply h-38 overflow-hidden cursor-pointer ml-1;

                        .code-load,
                        .code-error {
                            @apply h-full flex items-center justify-center w-5 mx-20;
                        }

                        .code-error {
                            @apply w-auto text-14 opacity-80;
                        }

                        img {
                            @apply h-full min-w-16;
                        }
                    }
                }

                .n-button {
                    @apply mt-24 w-full;
                }

                .login-switch {
                    @apply text-text-tips;

                    a {
                        @apply text-primary-color;
                        text-decoration: none;
                    }
                }
            }
        }

        .login-bottom {
            @apply flex items-center justify-between mt-24 w-388;

            .login-setting {
                @apply flex items-center cursor-pointer;
            }

            .login-forgot {
                @apply text-text-tips;

                a {
                    @apply text-primary-color;
                    text-decoration: none;
                }
            }
        }
    }
}

input:-webkit-autofill {
    -webkit-box-shadow: 0 0 0px 1000px white inset;
}

.dark input:-webkit-autofill {
    -webkit-box-shadow: 0 0 0px 1000px #2b2b2b inset;
    -webkit-text-fill-color: #ffffff;
}
</style>
