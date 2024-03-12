package zone

import "github.com/cilium/cilium/pkg/lock"

var zoneIDAlloc = NewZoneAllocator()

type ZoneAlloc struct {
	// Protects entitiesID, entities.
	lock.RWMutex

	entitiesID map[uint8]string
	entities   map[string]uint8

	nextID uint8
	maxID  uint8
}

func NewZoneAllocator() *ZoneAlloc {
	return &ZoneAlloc{
		entitiesID: map[uint8]string{},
		entities:   map[string]uint8{},
		nextID:     1,
		maxID:      0xff,
	}
}

func (alloc *ZoneAlloc) getID(zone string) uint8 {
	if zone == "" {
		return 0
	}
	alloc.Lock()
	defer alloc.Unlock()
	id, ok := alloc.entities[zone]
	if !ok {
		if alloc.nextID == alloc.maxID {
			// Shouldn't happen, so siltenly falling back to no zone information.
			return 0
		}
		id = alloc.nextID
		alloc.entities[zone] = id
		alloc.entitiesID[id] = zone
		alloc.nextID++
	}
	return id
}

func (alloc *ZoneAlloc) getZone(id uint8) string {
	if id == 0 {
		return ""
	}
	alloc.RLock()
	defer alloc.RUnlock()
	return alloc.entitiesID[id]
}

func GetID(zone string) uint8 {
	return zoneIDAlloc.getID(zone)
}

func GetZone(id uint8) string {
	return zoneIDAlloc.getZone(id)
}
