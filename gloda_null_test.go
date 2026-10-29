package main

import (
	"database/sql"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The FTS content table allows NULL in every text column, and real profiles
// hold thousands of such rows. They must come back as empty strings instead of
// failing the whole query with a Scan error.
var _ = Describe("Gloda.Search with NULL text columns", func() {
	var g *Gloda

	BeforeEach(func() {
		tmp, err := os.CreateTemp("", "gloda-null-*.sqlite")
		Expect(err).NotTo(HaveOccurred())
		tmp.Close()
		DeferCleanup(os.Remove, tmp.Name())
		seed, err := os.ReadFile("testdata/gloda_seed.sql")
		Expect(err).NotTo(HaveOccurred())
		db, err := sql.Open("sqlite", "file:"+tmp.Name())
		Expect(err).NotTo(HaveOccurred())
		_, err = db.Exec(string(seed) + `
INSERT INTO messages VALUES (20, 1, 201, 1700500000000000, 'null-body@example.com', 0, NULL);
INSERT INTO messages VALUES (21, 1, 202, 1700400000000000, 'null-all@example.com', 0, NULL);
INSERT INTO messagesText_content VALUES (20, NULL, 'No body', '', 'dave@example.com', 'alice@example.com');
INSERT INTO messagesText_content VALUES (21, NULL, NULL, NULL, NULL, NULL);`)
		Expect(err).NotTo(HaveOccurred())
		db.Close()
		g, err = openGlodaAt(tmp.Name())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(g.Close)
	})

	It("returns a message with a NULL body", func() {
		res, err := g.Search(SearchQuery{Subject: "No body", Limit: 10})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(HaveLen(1))
		Expect(res[0].Subject).To(Equal("No body"))
		Expect(res[0].Snippet).To(BeEmpty())
	})

	It("lists recent messages even when some have NULL columns", func() {
		res, err := g.Recent("", 10)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(HaveLen(5))
		Expect(res[0].Subject).To(Equal("No body"))
		Expect(res[1].Subject).To(BeEmpty())
		Expect(res[1].Author).To(BeEmpty())
	})
})
