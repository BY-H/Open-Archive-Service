package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	sms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sms/v20210111"
)

// JWT密钥
var jwtSecret = []byte("NWFhOaHlYtdLR2fdlQqUj8CSXgb2ebnN2DcjlXfV8zZ")

var credential *common.Credential

var smsClient *sms.Client

var db *gorm.DB

type Config struct {
	Server struct {
		Port int `mapstructure:"port"`
	} `mapstructure:"server"`

	Tencent struct {
		SecretID  string `mapstructure:"secret_id"`
		SecretKey string `mapstructure:"secret_key"`

		SMS struct {
			AppID      string `mapstructure:"app_id"`
			SignName   string `mapstructure:"sign_name"`
			TemplateID string `mapstructure:"template_id"`
		} `mapstructure:"sms"`
	} `mapstructure:"tencent"`

	Dsn string `mapstructure:"dsn"`
}

var Cfg *Config

func InitConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("read config failed: %v", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("unmarshal config failed: %v", err)
	}

	Cfg = &cfg
}

// ---------------- 数据库模型 ----------------

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique;not null"`
	Password  string `gorm:"not null"`
	Role      string `gorm:"type:enum('admin','user');default:'user'"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Archive struct {
	ID              uint   `gorm:"primaryKey"`
	ArchiveNo       string `gorm:"not null"` // 档案号
	Title           string `gorm:"not null"` // 题名
	Description     string
	FormTime        string `gorm:"not null"` // 档案形成时间
	RetentionPeriod string `gorm:"not null"` // 保管期限
	FilePath        string `gorm:"not null"`
	UploadedBy      uint   `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Comment struct {
	ID        uint   `gorm:"primaryKey"`
	ArchiveID uint   `gorm:"not null"`
	UserID    uint   `gorm:"not null"`
	Content   string `gorm:"not null"`
	CreatedAt time.Time
}

type ArchiveStat struct {
	ArchiveID     uint `gorm:"primaryKey"`
	ViewCount     int  `gorm:"default:0"`
	DownloadCount int  `gorm:"default:0"`
}

// ---------------- 数据库初始化 ----------------

func initDB() {
	dsn := Cfg.Dsn
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("数据库连接失败: " + err.Error())
	}

	// 自动迁移
	db.AutoMigrate(&User{}, &Archive{}, &Comment{}, &ArchiveStat{}, &Rating{}, &LoginStat{})
	fmt.Println("数据库表初始化完成")
}

func initSmsClient() {
	credential = common.NewCredential(
		Cfg.Tencent.SecretID,
		Cfg.Tencent.SecretKey,
	)
	cpf := profile.NewClientProfile()
	/* SDK默认使用POST方法。
	 * 如果您一定要使用GET方法，可以在这里设置。GET方法无法处理一些较大的请求 */
	cpf.HttpProfile.ReqMethod = "POST"
	cpf.HttpProfile.ReqTimeout = 10 // 请求超时时间，单位为秒(默认60秒)
	/* 指定接入地域域名，默认就近地域接入域名为 sms.tencentcloudapi.com ，也支持指定地域域名访问，例如广州地域的域名为 sms.ap-guangzhou.tencentcloudapi.com */
	cpf.HttpProfile.Endpoint = "sms.tencentcloudapi.com"
	/* SDK默认用TC3-HMAC-SHA256进行签名，非必要请不要修改这个字段 */
	cpf.SignMethod = "HmacSHA1"
	smsClient, _ = sms.NewClient(credential, "ap-guangzhou", cpf)
}

// ---------------- JWT ----------------

func generateJWT(username string, role string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少 Token"})
			c.Abort()
			return
		}

		// 必须从 "Bearer xxxxx" 中提取真正 token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 格式错误"})
			c.Abort()
			return
		}

		tokenString := parts[1] // <- 只取真正的JWT

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 无效"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("username", claims["username"])
		c.Set("role", claims["role"])
		c.Next()
	}
}

func generateCode() string {
	return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
}

// ---------------- 发送短信函数 ----------------
func sendSMS(phone string, templateID string, params []string) error {
	req := sms.NewSendSmsRequest()

	// 应用 ID（短信控制台里有）
	req.SmsSdkAppId = common.StringPtr(Cfg.Tencent.SMS.AppID)

	// 短信签名（必须是已审核通过的）
	req.SignName = common.StringPtr(Cfg.Tencent.SMS.SignName)

	// 模板 ID
	req.TemplateId = common.StringPtr(templateID)

	// 模板参数
	req.TemplateParamSet = common.StringPtrs(params)

	// 手机号（必须是 E.164 格式）
	req.PhoneNumberSet = common.StringPtrs([]string{
		"+86" + phone,
	})

	resp, err := smsClient.SendSms(req)
	if err != nil {
		return err
	}

	fmt.Printf("SMS response: %+v\n", resp.Response)

	return nil
}

type SmsCodeItem struct {
	Code      string
	ExpiresAt time.Time
}

var smsCodeStore = struct {
	sync.RWMutex
	data map[string]SmsCodeItem
}{
	data: make(map[string]SmsCodeItem),
}

type SmsSendRecord struct {
	LastSend time.Time
}

var smsSendLimiter = struct {
	sync.Mutex
	data map[string]SmsSendRecord
}{
	data: make(map[string]SmsSendRecord),
}

func canSendSms(phone string, interval time.Duration) bool {
	smsSendLimiter.Lock()
	defer smsSendLimiter.Unlock()

	record, exists := smsSendLimiter.data[phone]
	if !exists {
		return true
	}

	return time.Since(record.LastSend) >= interval
}

func markSmsSent(phone string) {
	smsSendLimiter.Lock()
	defer smsSendLimiter.Unlock()

	smsSendLimiter.data[phone] = SmsSendRecord{
		LastSend: time.Now(),
	}
}

func setSmsCode(phone, code string, ttl time.Duration) {
	smsCodeStore.Lock()
	defer smsCodeStore.Unlock()

	smsCodeStore.data[phone] = SmsCodeItem{
		Code:      code,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func getSmsCode(phone string) (string, bool) {
	smsCodeStore.RLock()
	item, ok := smsCodeStore.data[phone]
	smsCodeStore.RUnlock()

	if !ok {
		return "", false
	}

	if time.Now().After(item.ExpiresAt) {
		deleteSmsCode(phone)
		return "", false
	}

	return item.Code, true
}

func deleteSmsCode(phone string) {
	smsCodeStore.Lock()
	defer smsCodeStore.Unlock()

	delete(smsCodeStore.data, phone)
}

type SmsCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

func sendCodeHandler(c *gin.Context) {
	var req SmsCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "手机号不能为空"})
		return
	}

	matched, _ := regexp.MatchString(`^1[3-9]\d{9}$`, req.Phone)
	if !matched {
		c.JSON(http.StatusBadRequest, gin.H{"error": "手机号格式错误"})
		return
	}

	// ⭐ 1️⃣ 60 秒频率限制
	if !canSendSms(req.Phone, 60*time.Second) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "验证码发送过于频繁，请 60 秒后再试",
		})
		return
	}

	code := generateCode()

	setSmsCode(req.Phone, code, 5*time.Minute)

	err := sendSMS(
		req.Phone,
		Cfg.Tencent.SMS.TemplateID, // 短信模板 ID
		[]string{code},             // 模板参数，验证码 {1}
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "短信发送失败"})
		return
	}

	markSmsSent(req.Phone)

	c.JSON(http.StatusOK, gin.H{
		"message": "验证码已发送",
	})
}

func startSmsCodeCleaner() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)

			now := time.Now()
			smsCodeStore.Lock()
			for phone, item := range smsCodeStore.data {
				if now.After(item.ExpiresAt) {
					delete(smsCodeStore.data, phone)
				}
			}
			smsCodeStore.Unlock()
		}
	}()
}

func startSmsLimiterCleaner() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)

			now := time.Now()
			smsSendLimiter.Lock()
			for phone, record := range smsSendLimiter.data {
				if now.Sub(record.LastSend) > 10*time.Minute {
					delete(smsSendLimiter.data, phone)
				}
			}
			smsSendLimiter.Unlock()
		}
	}()
}

// ---------------- 登录接口 ----------------

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginStat struct {
	ID        uint `gorm:"primaryKey"`
	Count     int  `gorm:"default:0"`
	UpdatedAt time.Time
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	var user User
	result := db.Where("username = ?", req.Username).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 校验 bcrypt 密码
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 登录次数 +1
	var stat LoginStat
	if err := db.First(&stat).Error; err != nil {
		db.Create(&LoginStat{Count: 1})
	} else {
		db.Model(&stat).UpdateColumn("count", gorm.Expr("count + 1"))
	}
	token, err := generateJWT(user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成 token 失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"role":  user.Role,
	})
}

// ---------------- 注册接口 ----------------

type RegisterRequest struct {
	Username   string `json:"username" binding:"required"` // 手机号
	Password   string `json:"password" binding:"required"`
	Code       string `json:"code" binding:"required"` // 短信验证码
	InviteCode string `json:"invite_code"`
}

func registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	phone := req.Username // ⭐ 关键：username 就是手机号

	// 1️⃣ 校验短信验证码
	code, ok := getSmsCode(phone)
	if !ok || code != req.Code {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码错误或已过期"})
		return
	}

	// 用完即删，防止重复注册
	deleteSmsCode(phone)

	// 2️⃣ 管理员邀请码
	const adminInviteCode = "ADMIN-2025-SECRET"
	role := "user"

	if req.InviteCode != "" {
		if req.InviteCode == adminInviteCode {
			role = "admin"
		} else {
			c.JSON(http.StatusForbidden, gin.H{"error": "邀请码错误，无法注册为管理员"})
			return
		}
	}

	// 3️⃣ 密码加密
	hashedPassword, _ := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)

	user := User{
		Username: phone, // 直接存手机号
		Password: string(hashedPassword),
		Role:     role,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "手机号已注册"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "注册成功",
		"role":    role,
	})
}

// ---------------- 上传档案接口 ----------------
func uploadArchiveHandler(c *gin.Context) {
	role := c.GetString("role")
	username := c.GetString("username")

	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限上传档案"})
		return
	}

	// 获取表单字段
	archiveNo := c.PostForm("archive_no")
	title := c.PostForm("title")
	desc := c.PostForm("description")
	formTime := c.PostForm("form_time")
	retention := c.PostForm("retention_period")

	// 校验字段
	if archiveNo == "" || title == "" || formTime == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要字段"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未收到文件"})
		return
	}

	// 保存文件
	uploadDir := "uploads"
	_ = os.MkdirAll(uploadDir, os.ModePerm)

	timestamp := time.Now().Unix()
	filePath := fmt.Sprintf("%s/%d_%s", uploadDir, timestamp, file.Filename)

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "文件保存失败"})
		return
	}

	// 查找用户 ID
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户不存在"})
		return
	}

	// 写入数据库
	archive := Archive{
		ArchiveNo:       archiveNo,
		Title:           title,
		Description:     desc,
		FormTime:        formTime,
		RetentionPeriod: retention,
		FilePath:        filePath,
		UploadedBy:      user.ID,
	}

	if err := db.Create(&archive).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库写入失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "上传成功",
		"archive": archive,
	})
}

// ---------------- 分页查询档案接口 ----------------

func listArchivesHandler(c *gin.Context) {
	// 页面参数
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "10")
	keyword := c.Query("keyword") // 可选

	// 转 int
	p, _ := strconv.Atoi(page)
	ps, _ := strconv.Atoi(pageSize)
	if p < 1 {
		p = 1
	}
	if ps < 1 {
		ps = 10
	}

	var archives []Archive
	var total int64

	query := db.Model(&Archive{})

	// 模糊搜索：档案号 OR 题名
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("archive_no LIKE ? OR title LIKE ?", like, like)
	}

	// 获取总数
	query.Count(&total)

	// 分页 + 排序
	query.Order("created_at DESC").
		Offset((p - 1) * ps).
		Limit(ps).
		Find(&archives)

	c.JSON(http.StatusOK, gin.H{
		"page":      p,
		"page_size": ps,
		"total":     total,
		"data":      archives,
	})
}

// ---------------- 下载档案接口 ----------------
func downloadArchiveHandler(c *gin.Context) {
	// 从 URL 参数获取档案 ID
	idStr := c.Query("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少档案 ID"})
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "档案 ID 格式错误"})
		return
	}

	var archive Archive
	if err := db.First(&archive, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "档案不存在"})
		return
	}

	if archive.FilePath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "档案文件不存在"})
		return
	}

	// 可选：记录下载次数
	var stat ArchiveStat
	if err := db.FirstOrCreate(&stat, ArchiveStat{ArchiveID: archive.ID}).Error; err == nil {
		db.Model(&stat).UpdateColumn("download_count", gorm.Expr("download_count + ?", 1))
	}

	// 返回文件，Content-Disposition 让浏览器下载
	c.FileAttachment(archive.FilePath, fmt.Sprintf("%s%s", archive.Title, getFileExtension(archive.FilePath)))
}

// 获取文件扩展名
func getFileExtension(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) > 1 {
		return "." + parts[len(parts)-1]
	}
	return ""
}

func DownloadStat(c *gin.Context) {
	role := c.GetString("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限"})
		return
	}

	var total int64
	// SUM(download_count)
	db.Model(&ArchiveStat{}).Select("SUM(download_count)").Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"total_download_count": total,
	})
}

func batchUploadHandler(c *gin.Context) {
	role := c.GetString("role")
	username := c.GetString("username")

	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限上传"})
		return
	}

	// 获取上传的 Excel 文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未收到文件"})
		return
	}

	// 只能是 .xlsx
	if !strings.HasSuffix(strings.ToLower(file.Filename), ".xlsx") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "只支持 .xlsx 文件"})
		return
	}

	tempPath := fmt.Sprintf("uploads/%d_%s", time.Now().Unix(), file.Filename)
	_ = os.MkdirAll("uploads", os.ModePerm)

	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "文件保存失败"})
		return
	}

	// 打开 Excel
	excel, err := excelize.OpenFile(tempPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析 Excel 失败"})
		return
	}

	sheetList := excel.GetSheetList()
	if len(sheetList) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Excel 文件无工作表"})
		return
	}

	firstSheet := sheetList[0]

	rows, err := excel.GetRows(firstSheet)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取 Excel 失败"})
		return
	}

	if len(rows) <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Excel 内容为空"})
		return
	}

	// 查找用户
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户不存在"})
		return
	}

	failCount := 0
	errors := []string{}
	archives := make([]Archive, 0)

	// 遍历每一行（从第 2 行开始）
	for i := 1; i < len(rows); i++ {
		row := rows[i]

		// 列校验
		if len(row) < 8 {
			failCount++
			errors = append(errors, fmt.Sprintf("第 %d 行列数不足", i+1))
			continue
		}

		quanzong := row[0]
		year := row[1]
		jianhao := row[2]
		archiveNo := quanzong + "-" + year + "-" + jianhao

		danghao := row[3]
		author := row[4]
		title := row[5]
		pages := row[6]
		formTime := row[7]

		desc := fmt.Sprintf("档号: %s；责任者: %s；页数: %s", danghao, author, pages)

		archives = append(archives, Archive{
			ArchiveNo:       archiveNo,
			Title:           title,
			Description:     desc,
			FormTime:        formTime,
			RetentionPeriod: "永久",
			FilePath:        "",
			UploadedBy:      user.ID,
		})
	}

	// 一次性写入数据库
	if err := db.CreateInBatches(&archives, 200).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "批量写入失败", "detail": err.Error()})
		return
	}

	successCount := len(archives)

	c.JSON(http.StatusOK, gin.H{
		"message":       "批量上传完成",
		"success_count": successCount,
		"fail_count":    failCount,
		"errors":        errors,
	})
}

// ---------------- 删除档案接口 ----------------
func deleteArchiveHandler(c *gin.Context) {
	role := c.GetString("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限删除档案"})
		return
	}

	// 从 URL 参数获取档案 ID
	idStr := c.Query("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少档案 ID"})
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "档案 ID 格式错误"})
		return
	}

	var archive Archive
	if err := db.First(&archive, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "档案不存在"})
		return
	}

	// 删除文件（如果存在）
	if archive.FilePath != "" {
		_ = os.Remove(archive.FilePath) // 忽略文件不存在的错误
	}

	// 删除下载统计（可选，但推荐）
	db.Where("archive_id = ?", archive.ID).Delete(&ArchiveStat{})

	// 删除档案记录
	if err := db.Delete(&archive).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "档案删除成功",
		"archive_id": archive.ID,
	})
}

type Rating struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Score     int       `json:"score"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

type RatingRequest struct {
	Score int `json:"score" binding:"required,min=1,max=5"`
}

func SubmitRating(c *gin.Context) {
	var req RatingRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "score 必须是 1~5 的整数",
		})
		return
	}

	ip := c.ClientIP()

	rating := Rating{
		Score: req.Score,
		IP:    ip,
	}

	if err := db.Create(&rating).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "评分成功，感谢反馈！",
	})
}

func AverageRating(c *gin.Context) {
	var avg float64
	db.Model(&Rating{}).Select("AVG(score)").Scan(&avg)

	c.JSON(http.StatusOK, gin.H{
		"average": avg,
	})
}

func GetLoginTimes(c *gin.Context) {
	role := c.GetString("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权限"})
		return
	}

	var stat LoginStat
	db.First(&stat)

	c.JSON(http.StatusOK, gin.H{
		"count": stat.Count,
		"time":  stat.UpdatedAt,
	})
}

// ---------------- 主函数 ----------------

func main() {
	InitConfig()
	initDB()
	initSmsClient()
	startSmsCodeCleaner()
	startSmsLimiterCleaner()

	r := gin.Default()
	// ---------------- CORS ----------------
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://192.168.99.16:5173", "http://127.0.0.1:5173", "*"}, // 前端地址
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.POST("/sms/send", sendCodeHandler)
	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)

	// 需要 Token 才能访问的路由
	auth := r.Group("/")
	auth.Use(authMiddleware())
	{
		auth.POST("/upload", uploadArchiveHandler)
		auth.GET("/archives", listArchivesHandler)
		auth.GET("/archives/download", downloadArchiveHandler)
		auth.POST("/archives/batch_upload", batchUploadHandler)
		auth.GET("/login_stat", GetLoginTimes)
		r.POST("/rating", SubmitRating)
		auth.DELETE("/archives", deleteArchiveHandler)
		auth.GET("/ratings/average", AverageRating)
		auth.GET("/archives/download_stat", DownloadStat)
	}

	fmt.Println("服务启动: http://localhost:8080")
	r.Run(fmt.Sprintf(":%d", Cfg.Server.Port))
}
