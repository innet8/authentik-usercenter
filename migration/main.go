package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL 驱动
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Postgr
	"gopkg.in/yaml.v2"
)

type Config struct {
	SOURCE string `yaml:"SOURCE"`

	MYSQL_HOST     string `yaml:"MYSQL_HOST"`
	MYSQL_PORT     string `yaml:"MYSQL_PORT"`
	MYSQL_DATABASE string `yaml:"MYSQL_DATABASE"`
	MYSQL_USERNAME string `yaml:"MYSQL_USERNAME"`
	MYSQL_PASSWORD string `yaml:"MYSQL_PASSWORD"`

	POSTGRES_HOST     string `yaml:"POSTGRES_HOST"`
	POSTGRES_PORT     string `yaml:"POSTGRES_PORT"`
	POSTGRES_DATABASE string `yaml:"POSTGRES_DATABASE"`
	POSTGRES_USERNAME string `yaml:"POSTGRES_USERNAME"`
	POSTGRES_PASSWORD string `yaml:"POSTGRES_PASSWORD"`
}

func main() {

	// 读取 .yml 文件内容
	yamlFile, err := ioutil.ReadFile("./config.yml")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// 解析 .yml 文件内容
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// 连接到 MySQL 数据库
	mysqlDB, err := sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s",
		config.MYSQL_USERNAME,
		config.MYSQL_PASSWORD,
		config.MYSQL_HOST,
		config.MYSQL_PORT,
		config.MYSQL_DATABASE,
	))
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer mysqlDB.Close()

	// 连接到 PostgreSQL 数据库
	postgresDB, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.POSTGRES_HOST,
		config.POSTGRES_PORT,
		config.POSTGRES_USERNAME,
		config.POSTGRES_PASSWORD,
		config.POSTGRES_DATABASE,
	))
	if err != nil {
		log.Fatal(err)

		os.Exit(1)
	}
	defer postgresDB.Close()

	// 查询 MySQL 中的数据
	rows, err := mysqlDB.Query("SELECT DISTINCT(email) FROM pre_users WHERE type in (2,3) AND deleted_at IS NULL")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer rows.Close()

	// 遍历查询结果并插入到 PostgreSQL
	total := 0
	imports := 0
	for rows.Next() {
		var email string
		err := rows.Scan(&email)
		if err != nil {
			log.Fatal(err)
		}

		total = total + 1

		// 检查 PostgreSQL 中是否已存在相同的数据
		var existingEmail string
		err = postgresDB.QueryRow("SELECT email FROM authentik_core_user WHERE username = $1", email).Scan(&existingEmail)
		if err == nil {
			// 如果已存在相同的数据，则跳过导入
			fmt.Printf("已存在跳过 '%s' \n", email)
			continue
		}

		// 插入
		uuid := uuid.New()
		currentTime := time.Now()
		formattedTime := currentTime.Format("2006-01-02 15:04:05")
		_, err = postgresDB.Exec(`
			INSERT INTO authentik_core_user (username,email,password,first_name,last_name,is_active,date_joined,uuid,name,password_change_date,attributes,path,type,is_verify_email,is_send_email)
			VALUES ($1,$2,'','','','t',$3,$4,$5,$6,'{}',$7,'external','t','f')
			`,
			email,
			email,
			formattedTime,
			uuid.String(),
			email,
			formattedTime,
			config.SOURCE,
		)
		if err != nil {
			fmt.Printf("导入邮箱 '%s' 失败 \n", email)
			log.Fatal(err)
		} else {
			imports = imports + 1
		}
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	fmt.Println("数据迁移完成")
	fmt.Println("总导出", total)
	fmt.Println("总导入", imports)
	fmt.Println("失败数", total-imports)
	fmt.Println("")

}
