<template>
    <div class="page-login child-view" :style="customStyles">
        <div class="login-body">
            <div class="login-box" :style="customStyles">
                <h2 class="login-title">
                    <span>{{ config.title || ( loginType == 'reg' ? $t("注册") : $t("登录")) }}</span>
                </h2>
                <p class="login-subtitle">
                    {{ config.subtitle || $t("输入您的凭证以访问您的帐户") }}
                </p>
                <transition name="login-mode">
                    <n-form ref="formRef" :rules="rules" label-placement="left" :model="formData">
                        <div v-if="loginMode == 'access'" class="login-access">
                            <n-form-item label="" path="email">
                                <n-input v-model:value="formData.email" @blur="onBlur" :placeholder="$t('输入您的账号')" clearable size="large">
                                    <template #prefix>
                                        <n-icon :component="MailOutline" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-form-item label="" path="password">
                                <n-input type="password" v-model:value="formData.password" @blur="onBlur" :placeholder="$t('输入您的密码')" clearable
                                    size="large">
                                    <template #prefix>
                                        <n-icon :component="LockClosedOutline" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-form-item label="" path="code" v-if="codeNeed">
                                <n-input class="code-load-input" v-model:value="code" :placeholder="$t('输入图形验证码')" clearable size="large">
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
                            <n-form-item label="" path="confirmPassword" v-if="loginType == 'reg'">
                                <n-input type="password" v-model:value="formData.confirmPassword"
                                    :placeholder="$t('输入确认密码')" clearable size="large">
                                    <template #prefix>
                                        <n-icon :component="LockClosedOutline" />
                                    </template>
                                </n-input>
                            </n-form-item>
                            <n-button v-if="loginType == 'login'" :loading="loadIng" @click="handleLogin" :type="config.btncolor"
                                size="large">{{ $t("登录") }}</n-button>
                            <n-button v-else type="primary" :loading="loadIng" @click="handleReg">{{ $t("注册") }}</n-button>
                            <div class="login-switch" v-if="config.switch !== 'false'">
                                <template v-if="loginType == 'login'">
                                    {{ $t("还没有帐号？") }}
                                    <a href="javascript:void(0)" @click="changeLoginType"> {{ $t("注册帐号") }}</a>
                                </template>
                                <template v-else>
                                    {{ $t("已经有帐号？") }}
                                    <a href="javascript:void(0)" @click="changeLoginType"> {{ $t("登录帐号") }}</a>
                                </template>
                            </div>
                        </div>
                    </n-form>
                </transition>
            </div>
        </div>
    </div>
</template>

<script lang="ts" setup>
import { ref } from "vue"
import { userLogin, userReg } from "@/api/modules/user"
import { useMessage,FormItemRule } from "naive-ui"
import { UserStore } from "@/store/user"
import { useRoute } from "vue-router"
import { MailOutline, LockClosedOutline, CheckmarkCircleOutline } from "@vicons/ionicons5"

const message = useMessage()
const route = useRoute()
const loadIng = ref<boolean>(false)
const code = ref("")
const codeUrl = ref("")
const codeLoad = ref(0)
const userState = UserStore()
const loginMode = ref("access") //qrcode
const codeNeed = ref(false)
const codeId = ref("")
const loginType = ref<String>("login")
const formRef = ref(null)
const formData = ref({
    email: "",
    password: "",
    confirmPassword: "",
    invite: "",
})

// 路由参数配置
const config = ref({
    language: route.query.language || 'zh',         //  显示语言 - en、zh、zh-cht、fr、id、ja、ko
    source: route.query.source  || '',              //  来源
    callback : route.query.callback || '',          //  登录成功后浏览器去往的地址
    title : route.query.title || '',                //  标题
    subtitle : route.query.subtitle || '',          //  标题下方的描述
    switch: route.query.switch || 'true',           //  打开切换注册的按钮
    color : route.query.color || '',                //  字体色 - 透明色：transparent 白色：white
    bgcolor : route.query.bgColor || 'white',       //  背景色 - 透明色：transparent 白色：white
    shadow : route.query.shadow || '',              //  阴影 - 不显示：none
    btncolor : route.query.btnColor || 'primary',   //  按钮色 - default、tertiary、primary、info、success、warning 和 error
    theme : route.query.theme ||   'default',       //  主题
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
        validator (rule: FormItemRule, value: string) {
            if (!value) {
                return new Error($t('请输入您的账号'))
            }
            // else if (!utils.isEmail(value)) {
            //     return new Error($t('请输入正确的邮箱'))
            // }
            return true
        },
        trigger:  ['input','blur']
    },
    password: {
        required: true,
        message: $t('输入您的密码'),
        trigger: ['input','blur']
    },
    confirmPassword: {
        required: true,
        validator (rule: FormItemRule, value: string) {
            if (!value) {
              return new Error($t('请再次确认密码'))
            }else if (value != formData.value.password) {
              return new Error($t('两次密码输入不一致'))
            }
            return true
        },
        trigger: ['input','blur'],
    },
})

// 登录
const handleLogin = () => {
    try {
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
                code_id: codeId.value,
                code: code.value,
            }).then(({ data, msg }) => {
                userState.info = data
                if(callback){
                    callback = callback.indexOf("?") == -1 ? callback + "?ak-token=" : callback + "&ak-token="
                    parent.window.location.href = callback + data.token
                }else{
                    parent.window.location.href =  window.location.origin + `/page/success?language=${config.value.language}&ak-token=${data.token}`
                }
            })
            .catch( res => {
                message.error( $t(res.data.response.data.msg) )
                if (res.data.code == "need") {
                    onBlur()
                }
            })
            .finally(() => {
                loadIng.value = false
            })
        })
    }catch (e) {

    }
}

// 注册
const handleReg = () => {
    try {
        formRef.value?.validate((errors) => {
            if (errors) {
                console.log(errors)
                return
            }
            loadIng.value = true
            userReg({
                username: formData.value.email,
                password: formData.value.password,
                source: (config.value.source + '') || 'sys-web',
            }).then(({ data,msg }) => {
                message.success( $t("注册成功") )
                loginType.value = "login"
            })
            .catch( res => {
                message.error( $t(res.data.response.data.msg) )
            }).finally(() => {
                loadIng.value = false
            })
        })
    }catch (e) {

    }
}

// 变更登录类型
const changeLoginType = () => {
    loginType.value == "login" ? (loginType.value = "reg") : (loginType.value = "login")
    if (loginType.value == "reg") {
        codeNeed.value = false
    } else {
        onBlur()
    }
}

// 判断要不要验证码
const onBlur = () => {
    // const upData = {
    //     email: formData.value.email,
    // }
    // needCode(upData)
    // .then(({ data }) => {
    //     codeNeed.value = data
    //     if (codeNeed.value) {
    //         refreshCode()
    //     }
    // })
}

// 刷新验证码
const refreshCode = () => {
    // codeImg()
    //     .then(({ data }) => {
    //         codeUrl.value = data.image_path
    //         codeId.value = data.captcha_id
    //     })
    //     .catch(() => {
    //         codeUrl.value = "error"
    //     })
}
</script>

<style lang="less" scoped>
.page-login {
    @apply bg-bg-login flex items-center;

    .login-body {
        @apply flex items-center flex-col max-h-full overflow-hidden py-32 w-full;

        .login-logo {
            @apply block w-84 h-84 bg-logo mb-36;
        }

        .login-box {
            @apply bg-bg-login-box shadow-login-box-Shadow rounded w-400 relative;
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
                @apply text-24 font-semibold text-center mt-30;
            }

            .login-subtitle {
                @apply text-14 text-text-tips text-center mt-12 px-12;
            }

            .login-qrcode {
                @apply flex items-center justify-center m-auto my-50;
            }

            .login-access {
                @apply mt-30 mx-40 mb-32;

                .n-input {
                    @apply mt-6;
                    transition: all 0s;
                }

                .code-load-input {
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
                    @apply mt-24 text-text-tips;

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
