
package xexloaderwv;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class XEXRttiDiscovery {
	private static final int MAX_NAME = 1024;
	private static final int MAX_BASES = 1024;

	public record Range(long start, long end) {
		boolean contains(long address, int size) {
			return address >= start && address + size <= end && (address & 3) == 0;
		}
	}

	public record Region(long start, byte[] bytes) {
		Range range() {
			return new Range(start, start + bytes.length);
		}
	}

	public record TypeDescriptor(long address, long typeInfoTable, String name) {
	}

	public record BaseDescriptor(long address, long type, long containedBases, int memberOffset, int vbtableOffset,
			int displacementOffset, long attributes, long hierarchy) {
	}

	public record Hierarchy(long address, long attributes, long array, List<BaseDescriptor> bases) {
	}

	public record Locator(long address, long type, long hierarchy, long offset, long constructorOffset) {
	}

	public record VirtualTable(long address, long locator, long firstFunction) {
	}

	public record Result(List<TypeDescriptor> types, List<Hierarchy> hierarchies, List<Locator> locators,
			List<VirtualTable> tables) {
	}

	private final List<Region> data;
	private final List<Range> code;
	private final BooleanSupplier cancelled;

	private XEXRttiDiscovery(List<Region> data, List<Range> code, BooleanSupplier cancelled) {
		this.data = data.stream().sorted(Comparator.comparingLong(Region::start)).toList();
		this.code = List.copyOf(code);
		this.cancelled = cancelled;
	}

	public static Result discover(List<Region> data, List<Range> code, BooleanSupplier cancelled) {
		return new XEXRttiDiscovery(data, code, cancelled).scan();
	}

	private void checkCancelled() {
		if (cancelled.getAsBoolean())
			throw new CancellationException("RTTI discovery cancelled");
	}

	private Region find(long address, int size) {
		for (Region region : data)
			if (region.range().contains(address, size))
				return region;
		return null;
	}

	private static long word(Region region, int offset) {
		byte[] b = region.bytes();
		return ((long) (b[offset] & 255) << 24) | ((long) (b[offset + 1] & 255) << 16)
				| ((long) (b[offset + 2] & 255) << 8) | (b[offset + 3] & 255);
	}

	private long word(long address) {
		Region region = find(address, 4);
		return region == null ? -1 : word(region, (int) (address - region.start()));
	}

	private boolean executable(long address) {
		for (Range range : code)
			if (range.contains(address, 4))
				return true;
		return false;
	}

	private String typeName(Region region, int start) {
		byte[] b = region.bytes();
		if (start + 4 > b.length || b[start] != '.' || b[start + 1] != '?' || b[start + 2] != 'A'
				|| (b[start + 3] != 'V' && b[start + 3] != 'U'))
			return null;
		for (int i = start + 4; i < b.length && i - start < MAX_NAME; i++) {
			int c = b[i] & 255;
			if (c == 0)
				return b[i - 1] == '@' ? new String(b, start, i - start, StandardCharsets.US_ASCII) : null;
			if (c < 33 || c > 126)
				return null;
		}
		return null;
	}

	private Hierarchy hierarchy(long address, long type, Map<Long, TypeDescriptor> types) {
		if (find(address, 16) == null || word(address) != 0)
			return null;
		long count = word(address + 8);
		long array = word(address + 12);
		if (count < 1 || count > MAX_BASES || find(array, (int) count * 4) == null)
			return null;
		List<BaseDescriptor> bases = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			long a = word(array + i * 4L);
			if (find(a, 28) == null)
				return null;
			long t = word(a);
			long n = word(a + 4);
			long h = word(a + 24);
			if (!types.containsKey(t) || n >= count - i || find(h, 16) == null)
				return null;
			if (i == 0 && (t != type || n != count - 1))
				return null;
			bases.add(new BaseDescriptor(a, t, n, (int) word(a + 8), (int) word(a + 12), (int) word(a + 16),
					word(a + 20), h));
		}
		return new Hierarchy(address, word(address + 4), array, List.copyOf(bases));
	}

	private Result scan() {
		Map<Long, Map<Long, TypeDescriptor>> groups = new TreeMap<>();
		for (Region region : data) {
			checkCancelled();
			int first = (int) ((-region.start()) & 3);
			for (int i = first; i <= region.bytes().length - 12; i += 4) {
				if ((i & 0x3fff) == first)
					checkCancelled();
				String name = typeName(region, i + 8);
				if (name == null || word(region, i + 4) != 0)
					continue;
				long vt = word(region, i);
				if (!executable(word(vt)))
					continue;
				long a = region.start() + i;
				groups.computeIfAbsent(vt, k -> new TreeMap<>()).put(a, new TypeDescriptor(a, vt, name));
			}
		}
		Map<Long, TypeDescriptor> types = Map.of();
		boolean ambiguous = false;
		for (var group : groups.values()) {
			if (group.size() > types.size()) {
				types = group;
				ambiguous = false;
			} else if (group.size() == types.size())
				ambiguous = true;
		}
		if (types.isEmpty() || ambiguous)
			return new Result(List.of(), List.of(), List.of(), List.of());
		Map<Long, Hierarchy> hierarchies = new TreeMap<>();
		Map<Long, Locator> locators = new TreeMap<>();
		for (Region region : data) {
			checkCancelled();
			int first = (int) ((-region.start()) & 3);
			for (int i = first; i <= region.bytes().length - 20; i += 4) {
				if ((i & 0x3fff) == first)
					checkCancelled();
				if (word(region, i) != 0)
					continue;
				long type = word(region, i + 12);
				if (!types.containsKey(type))
					continue;
				long h = word(region, i + 16);
				Hierarchy hierarchy = hierarchies.get(h);
				if (hierarchy == null)
					hierarchy = hierarchy(h, type, types);
				if (hierarchy == null || hierarchy.bases().get(0).type() != type)
					continue;
				hierarchies.put(h, hierarchy);
				long a = region.start() + i;
				locators.put(a, new Locator(a, type, h, word(region, i + 4), word(region, i + 8)));
			}
		}
		var pending = new ArrayDeque<>(hierarchies.values());
		while (!pending.isEmpty()) {
			checkCancelled();
			for (BaseDescriptor base : pending.removeFirst().bases()) {
				if (hierarchies.containsKey(base.hierarchy()))
					continue;
				Hierarchy h = hierarchy(base.hierarchy(), base.type(), types);
				if (h != null) {
					hierarchies.put(h.address(), h);
					pending.addLast(h);
				}
			}
		}
		List<VirtualTable> tables = new ArrayList<>();
		for (Region region : data) {
			checkCancelled();
			int first = (int) ((-region.start()) & 3);
			for (int i = first; i <= region.bytes().length - 8; i += 4) {
				if ((i & 0x3fff) == first)
					checkCancelled();
				long locator = word(region, i);
				if (!locators.containsKey(locator))
					continue;
				long function = word(region, i + 4);
				if (executable(function))
					tables.add(new VirtualTable(region.start() + i + 4, locator, function));
			}
		}
		return new Result(List.copyOf(types.values()), List.copyOf(hierarchies.values()),
				List.copyOf(locators.values()), List.copyOf(tables));
	}
}
