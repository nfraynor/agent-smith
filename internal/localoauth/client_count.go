package localoauth

import bolt "go.etcd.io/bbolt"

// ClientCount bounds public dynamic registrations so an unauthenticated caller
// cannot grow the embedded database indefinitely.
func (s *Store) ClientCount() (int, error) {
	count := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketClients).ForEach(func(_, _ []byte) error {
			count++
			return nil
		})
	})
	return count, err
}
