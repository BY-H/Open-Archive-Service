package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// JWT密钥
var jwtSecret = []byte("NWFhOaHlYtdLR2fdlQqUj8CSXgb2ebnN2DcjlXfV8zZ")

var db *gorm.DB

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
	dsn := "root:429520hby@tcp(undefiner.cn:3306)/OpenArchive?charset=utf8mb4&parseTime=True&loc=Local"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("数据库连接失败: " + err.Error())
	}

	// 自动迁移
	db.AutoMigrate(&User{}, &Archive{}, &Comment{}, &ArchiveStat{}, &Rating{}, &LoginStat{})
	fmt.Println("数据库表初始化完成")
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
	Username   string `json:"username"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"` // 新增：邀请码
}

func registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	// 固定邀请码
	const adminInviteCode = "ADMIN-2025-SECRET"

	// 判断角色
	role := "user" // 默认普通用户

	if req.InviteCode != "" {
		if req.InviteCode == adminInviteCode {
			role = "admin" // 邀请码正确，允许管理员注册
		} else {
			c.JSON(http.StatusForbidden, gin.H{"error": "邀请码错误，无法注册为管理员"})
			return
		}
	}

	// bcrypt 加密密码
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	user := User{
		Username: req.Username,
		Password: string(hashedPassword),
		Role:     role,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
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
	if archiveNo == "" || title == "" || formTime == "" || retention == "" {
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
	initDB()

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
		auth.GET("/ratings/average", AverageRating)
		auth.GET("/archives/download_stat", DownloadStat)
	}

	fmt.Println("服务启动: http://localhost:8080")
	r.Run(":8080")
}
