<template >
    <div class="page-reset child-view">
        <div class="reset-body">
            <div class="reset-box">
                <h3 class="text-32 font-semibold text-center text-text-li">{{ $t('重置密码') }}</h3>
                <div class="bg-[#F8F8F8] rounded px-16 py-12 mb-16 mt-32">
                    <p class=" text-text-tips text-14 "> {{ $t('您的新密码长度必须至少是6个字符，并且至少包含2种不同类型字符') }}
                    </p>
                </div>
                <transition name="login-mode">
                    <n-form ref="formRef" :rules="rules" label-placement="left" :show-require-mark="false" :model="formData">
                        <n-form-item path="password">
                            <n-input type="password" v-model:value="formData.password" :placeholder="$t('请设置新密码')" clearable>
                                <template #prefix>
                                    <n-icon :component="LockClosed" />
                                </template>
                            </n-input>
                        </n-form-item>
                        <n-button class="w-full" type="primary" :loading="loadIng" @click="handleReset">{{ $t("重置密码 ")
                        }}</n-button>
                    </n-form>
                </transition>


            </div>
        </div>
    </div>
</template>
<script setup lang="ts">
import { LockClosed } from "@vicons/ionicons5"
import { resetPassword } from "@/api/modules/user"
import { useMessage } from "@/utils/messageAll"
import { useRoute } from 'vue-router'

const loadIng = ref<boolean>(false)
const message = useMessage()
const route = useRoute()
const formData = ref({
    password: "",
})
const rules = ref({
    password: {
        required: true,
        message: $t('请输入密码'),
        trigger: ['input', 'blur']
    },
})

// 找回密码
const handleReset = () => {
    // if(!route.query.link_code)return
    loadIng.value = true
    resetPassword({
        step: 2,
        new_password: formData.value.password,
        link_code: route.query.link_code,
    }).then(({ data, msg }) => {
        message.success($t("重置成功！"))
        setTimeout(() => {
            window.location.href = route.query.source_url.toString();
        }, 3000);
    })
        .catch(res => {
            message.error($t(res.msg))
        }).finally(() => {
            loadIng.value = false
        })

}
</script>
<style scoped>
.page-reset {
    @apply bg-bg-login flex items-center;
}

.reset-body {
    @apply flex items-center flex-col max-h-full overflow-hidden py-5 w-full;
}

.reset-box {
    @apply bg-bg-login-box shadow-login-box-Shadow rounded w-368 p-40 relative;
}
</style>
