import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import {defineConfig} from "eslint/config";

export default defineConfig([
    {
        files: ["**/*.{js,mjs,cjs,ts,mts,cts}"],
        plugins: {js},
        extends: ["js/recommended"],
        languageOptions: {globals: globals.node},
        rules: {
            indent: ["warn", 4, { SwitchCase: 1 }],
            "no-const-assign": "error",
            "no-constant-condition": ["error", { checkLoops: false }],
            "no-debugger": "error",
            "no-dupe-args": "error",
            "no-dupe-class-members": "error",
            "no-dupe-keys": "error",
            "no-duplicate-case": "error",
            "no-empty-pattern": "error",
            "no-ex-assign": "error",
            "no-func-assign": "error",
            "no-import-assign": "error",
            "no-irregular-whitespace": "error",
            "no-loss-of-precision": "error",
            "no-new-native-nonconstructor": "error",
            "no-obj-calls": "error",
            "no-prototype-builtins": "off",
            "no-redeclare": "error",
            "no-self-assign": "error",
            "no-self-compare": "error",
            "no-shadow-restricted-names": "error",
            "no-sparse-arrays": "error",
            "no-this-before-super": "error",
            "no-undef": "warn",
            "no-unreachable": "error",
            "no-unsafe-finally": "error",
            "no-unsafe-negation": "error",
            "no-unused-private-class-members": "warn",
            "no-unused-vars": ["warn", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
            "no-use-before-define": ["warn", { functions: false, classes: true, variables: true }],
            "require-yield": "error",
            "use-isnan": "error",
            "valid-typeof": "error",
        }
    },
    tseslint.configs.recommended,
]);
