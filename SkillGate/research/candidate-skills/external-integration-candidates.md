# SkillGate 外部整合能力候選

## 目的
這份文件用來記錄：哪些外部 skills / modules 值得作為 SkillGate 的**對照組、規則來源、或整合能力候選**。

原則：
- 不是把外部 skill 直接當成 SkillGate 本身
- 而是把它們當作：
  - 規則來源
  - 能力候選
  - 產品化靈感

---

## 候選 1：useai-pro/openclaw-skills-security
### 目前定位
- **對照組：是**
- **規則來源：是**
- **整合能力候選：是**
- **直接整包進 production：否**

### 有價值的模組
#### 1. dependency-auditor
**可吸收價值**
- package legitimacy
- typosquatting
- publisher identity
- install hooks
- transitive deps
- vuln DB 參考
- license compatibility

**SkillGate 可產品化方向**
- Fast Gate dependency risk score
- Deep Gate supply chain module
- dependency report template

---

#### 2. permission-auditor
**可吸收價值**
- 權限解釋
- 危險組合判定
- 最小權限建議
- plain-language 風險翻譯

**SkillGate 可產品化方向**
- permission fit scoring
- 權限風險矩陣
- 權限治理報告欄位

---

#### 3. sandbox-guard
**可吸收價值**
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--network none`
- `--read-only`
- resource limits
- non-root user

**SkillGate 可產品化方向**
- L2 sandbox profile 範本
- execution isolation layer
- enterprise 配置模板

**限制**
- 偏 Docker-only
- 需要 SkillGate 擴成多 sandbox 模型（SecureClaw / others）

---

### 總評
這包東西很像：
- SkillGate 的規則骨架來源
- 不是 SkillGate 的終點
- 但非常值得吸收、改寫、產品化

---

## 後續處理原則
### 可以做
- 吸收規則
- 改寫成 SkillGate 流程
- 整合進報告包與評分邏輯
- 當成外部能力來源之一

### 不應直接做
- 不應宣稱這些能力是我們全部自研
- 不應把整包直接等同 SkillGate
- 不應在未完成審查前直接進 production

---

## 下一步
1. 把 dependency / permission / sandbox 三塊吸收進 SkillGate 架構
2. 把它們映射到 Fast Gate / Deep Gate / Batch Mode
3. 後續再決定是否需要針對單個模組做更深整合或下載
