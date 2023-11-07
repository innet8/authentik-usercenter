module.exports = {
    root: true,
    env: {
        browser: true,
        es2021: true,
        node: true,
        jest: true,
        es6: true,
        $t: true,
    },
    extends: [
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended",
        "plugin:vue/vue3-essential",
        "plugin:prettier/recommended",
    ],
    parserOptions: {
        ecmaVersion: "latest",
        parser: "@typescript-eslint/parser",
        sourceType: "module",
        allowImportExportEverywhere: true,
        ecmaFeatures: {
            jsx: true,
        },
    },
    globals: {
        cy: "readonly",
        Cypress: "readonly",
        clipboardData: "readonly",
        PKG_VERSION: true,
        defineProps: "readonly",
        defineEmits: "readonly",
    },
    settings: {
        "import/extensions": [".js", ".jsx", ".ts", ".tsx"],
    },
    plugins: ["@typescript-eslint", "vue"],
    rules: {
        indent: ["off"],
        "linebreak-style": ["error", "unix"],
        quotes: ["error", "double"],
        semi: ["warn", "never"],
        "no-console": [
            "error",
            {
                allow: ["info", "warn", "error"],
            },
        ],
        // code style config
        "no-continue": "off",
        "no-restricted-syntax": "off",
        "no-plusplus": "off",
        "no-param-reassign": "off",
        "no-shadow": "off",
        "no-underscore-dangle": "off",
        "no-unused-vars": "off",
        "no-unused-expressions": "off",
        "no-return-assign": "off",
        "no-use-before-define": "off",
        "func-names": "off",
        "guard-for-in": "off",
        "consistent-return": "off",
        "no-restricted-globals": "off",
        "default-param-last": "off",
        "default-case": "off",
        "prefer-spread": "off",

        // import config
        "import/extensions": "off",
        "import/no-unresolved": "off",
        "import/no-extraneous-dependencies": "off",
        "import/prefer-default-export": "off",
        "import/no-relative-packages": "off",

        // typescript config
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/explicit-module-boundary-types": "off",
        "@typescript-eslint/no-require-imports": 0,
        "@typescript-eslint/no-var-requires": 0,
        "@typescript-eslint/prefer-for-of": 0,
        "@typescript-eslint/ban-types": 0,
        "@typescript-eslint/no-unused-vars": [
            1,
            {
                argsIgnorePattern: "^_",
                varsIgnorePattern: "^_",
            },
        ],
        "@typescript-eslint/no-empty-function": 0,
        "@typescript-eslint/ban-ts-comment": 0,
        "vue/require-default-prop": 0,
        "vue/multi-word-component-names": 0,
        "vue/no-deprecated-slot-attribute": 0,
    },
    overrides: [
        {
            files: ["*.vue"],
            rules: {
                "vue/component-name-in-template-casing": [2, "kebab-case"],
                "vue/require-default-prop": 0,
            },
        },
        {
            files: ["**/_example/*", "script/**/*", "script/*", "*.js", "site/**/*", "site/*"],
            rules: {
                "no-var-requires": 0,
                "no-console": 0,
                "no-unused-expressions": 0,
                "no-alert": 0,
            },
        },
        {
            files: ["*.ts", "*.tsx"],
            rules: {
                "@typescript-eslint/explicit-function-return-type": 0,
            },
        },
        {
            files: ["*.test.js"],
            rules: {
                "import/no-dynamic-require": "off",
                "global-require": "off",
            },
        },
        {
            files: "*",
        },
    ],
};
