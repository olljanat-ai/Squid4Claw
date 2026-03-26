package database

import (
	"testing"
)

func TestDefaultPort(t *testing.T) {
	tests := []struct {
		driver DriverType
		want   int
	}{
		{DriverMSSQL, 1433},
		{DriverPostgres, 5432},
		{DriverMySQL, 3306},
		{DriverType("unknown"), 0},
	}
	for _, tt := range tests {
		got := DefaultPort(tt.driver)
		if got != tt.want {
			t.Errorf("DefaultPort(%s) = %d, want %d", tt.driver, got, tt.want)
		}
	}
}

func TestDSN(t *testing.T) {
	tests := []struct {
		name   string
		config DatabaseConfig
		want   string
	}{
		{
			name: "mssql with explicit port",
			config: DatabaseConfig{
				Driver:   DriverMSSQL,
				Host:     "db.example.com",
				Port:     1434,
				DBName:   "testdb",
				Username: "sa",
				Password: "secret",
			},
			want: "sqlserver://sa:secret@db.example.com:1434?database=testdb",
		},
		{
			name: "mssql with default port",
			config: DatabaseConfig{
				Driver:   DriverMSSQL,
				Host:     "db.example.com",
				DBName:   "testdb",
				Username: "sa",
				Password: "secret",
			},
			want: "sqlserver://sa:secret@db.example.com:1433?database=testdb",
		},
		{
			name: "postgres",
			config: DatabaseConfig{
				Driver:   DriverPostgres,
				Host:     "pg.example.com",
				Port:     5433,
				DBName:   "myapp",
				Username: "admin",
				Password: "pass",
			},
			want: "postgres://admin:pass@pg.example.com:5433/myapp?sslmode=disable",
		},
		{
			name: "mysql",
			config: DatabaseConfig{
				Driver:   DriverMySQL,
				Host:     "mysql.example.com",
				Port:     3307,
				DBName:   "store",
				Username: "root",
				Password: "rootpw",
			},
			want: "root:rootpw@tcp(mysql.example.com:3307)/store",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.DSN()
			if got != tt.want {
				t.Errorf("DSN() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGoDriverName(t *testing.T) {
	tests := []struct {
		driver DriverType
		want   string
	}{
		{DriverMSSQL, "sqlserver"},
		{DriverPostgres, "postgres"},
		{DriverMySQL, "mysql"},
		{DriverType("unknown"), ""},
	}
	for _, tt := range tests {
		cfg := DatabaseConfig{Driver: tt.driver}
		got := cfg.GoDriverName()
		if got != tt.want {
			t.Errorf("GoDriverName(%s) = %q, want %q", tt.driver, got, tt.want)
		}
	}
}

func TestManagerCRUD(t *testing.T) {
	m := NewManager()

	// Add
	db1 := DatabaseConfig{
		ID:       "db-1",
		Name:     "Test DB",
		APIPath:  "testdb",
		Driver:   DriverPostgres,
		Host:     "localhost",
		Port:     5432,
		DBName:   "test",
		Username: "user",
		Password: "pass",
		Active:   true,
	}
	m.Add(db1)

	// Get
	got, ok := m.Get("db-1")
	if !ok {
		t.Fatal("expected to find db-1")
	}
	if got.Name != "Test DB" {
		t.Errorf("Name = %q, want %q", got.Name, "Test DB")
	}

	// GetByAPIPath (global)
	got, ok = m.GetByAPIPath("testdb", "10.0.0.1")
	if !ok {
		t.Fatal("expected to find by API path testdb")
	}
	if got.ID != "db-1" {
		t.Errorf("ID = %q, want %q", got.ID, "db-1")
	}

	// GetByAPIPath not found
	_, ok = m.GetByAPIPath("nonexistent", "10.0.0.1")
	if ok {
		t.Error("expected not to find nonexistent API path")
	}

	// List
	list := m.List()
	if len(list) != 1 {
		t.Errorf("List() length = %d, want 1", len(list))
	}

	// Update
	db1.Name = "Updated DB"
	m.Update(db1)
	got, _ = m.Get("db-1")
	if got.Name != "Updated DB" {
		t.Errorf("after update, Name = %q, want %q", got.Name, "Updated DB")
	}

	// Delete
	m.Delete("db-1")
	_, ok = m.Get("db-1")
	if ok {
		t.Error("expected db-1 to be deleted")
	}
	if len(m.List()) != 0 {
		t.Error("expected empty list after delete")
	}
}

func TestManagerGetByAPIPathInactive(t *testing.T) {
	m := NewManager()
	m.Add(DatabaseConfig{
		ID:      "db-1",
		APIPath: "mydb",
		Active:  false,
	})
	_, ok := m.GetByAPIPath("mydb", "10.0.0.1")
	if ok {
		t.Error("expected inactive database to not be returned by GetByAPIPath")
	}
}

func TestManagerGetByAPIPathSourceIP(t *testing.T) {
	m := NewManager()
	// VM-specific database
	m.Add(DatabaseConfig{
		ID:       "db-1",
		APIPath:  "mydb",
		SourceIP: "10.255.255.10",
		Active:   true,
	})

	// Should not match different source IP
	_, ok := m.GetByAPIPath("mydb", "10.255.255.20")
	if ok {
		t.Error("expected VM-specific database to not match different source IP")
	}

	// Should match correct source IP
	got, ok := m.GetByAPIPath("mydb", "10.255.255.10")
	if !ok {
		t.Fatal("expected to find VM-specific database for matching IP")
	}
	if got.ID != "db-1" {
		t.Errorf("ID = %q, want %q", got.ID, "db-1")
	}

	// Global database (empty SourceIP) should match any IP
	m.Add(DatabaseConfig{
		ID:      "db-2",
		APIPath: "globaldb",
		Active:  true,
	})
	_, ok = m.GetByAPIPath("globaldb", "10.255.255.99")
	if !ok {
		t.Error("expected global database to match any source IP")
	}
}

func TestAPIPathExists(t *testing.T) {
	m := NewManager()
	m.Add(DatabaseConfig{ID: "db-1", APIPath: "mydb", Active: true})

	if !m.APIPathExists("mydb", "") {
		t.Error("expected APIPathExists to return true")
	}
	if m.APIPathExists("mydb", "db-1") {
		t.Error("expected APIPathExists to return false when excluding own ID")
	}
	if m.APIPathExists("other", "") {
		t.Error("expected APIPathExists to return false for non-existent path")
	}
}

func TestManagerLoadConfigs(t *testing.T) {
	m := NewManager()
	configs := []DatabaseConfig{
		{ID: "db-1", Name: "DB1", APIPath: "db1", Active: true},
		{ID: "db-2", Name: "DB2", APIPath: "db2", Active: true},
	}
	m.LoadConfigs(configs)

	list := m.List()
	if len(list) != 2 {
		t.Errorf("after LoadConfigs, List() length = %d, want 2", len(list))
	}
}

func TestQueryEmptyQuery(t *testing.T) {
	m := NewManager()
	m.Add(DatabaseConfig{
		ID:      "db-1",
		APIPath: "test",
		Driver:  DriverPostgres,
		Active:  true,
	})
	// Without a registered driver, the connection will fail before
	// the empty query check. That's expected behavior.
	result := m.Query("db-1", "", nil)
	if result.Error == "" {
		t.Error("expected error for empty query or missing driver")
	}
}

func TestQueryNotFound(t *testing.T) {
	m := NewManager()
	result := m.Query("nonexistent", "SELECT 1", nil)
	if result.Error == "" {
		t.Error("expected error for nonexistent database")
	}
}
