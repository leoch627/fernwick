#import <Cocoa/Cocoa.h>

// The speed item sits in the menu bar beside the tray icon while connected: upload over
// download, right-aligned, with a row of eight bars for each (pink up, blue down). The
// image redraws for the menu bar's own appearance, so the text stays readable over
// light and dark wallpapers.

extern void speedBarClicked(void);

@interface SpeedBarTarget : NSObject
- (void)clicked:(id)sender;
@end
@implementation SpeedBarTarget
- (void)clicked:(id)sender {
	speedBarClicked();
}
@end

static NSStatusItem *speedItem;
static SpeedBarTarget *speedTarget;

static const CGFloat cellWidth = 3, cellGap = 1.5, rowHeight = 7, rowGap = 2, barsGap = 5;

static NSFont *speedFont(void) {
	return [NSFont monospacedDigitSystemFontOfSize:9 weight:NSFontWeightMedium];
}

// The widest text the item ever shows, so the item never changes width.
static CGFloat speedTextWidth(void) {
	NSDictionary *attributes = @{NSFontAttributeName: speedFont()};
	CGFloat width = 0;
	for (NSString *sample in @[@"888 MB/s", @"888 KB/s", @"8.8 GB/s", @"888 B/s"]) {
		width = MAX(width, [sample sizeWithAttributes:attributes].width);
	}
	return ceil(width);
}

NSImage *speedBarImage(NSString *up, NSString *down, int upLevel, int downLevel, CGFloat height) {
	CGFloat textWidth = speedTextWidth();
	CGFloat barsWidth = 8 * cellWidth + 7 * cellGap;
	NSSize size = NSMakeSize(textWidth + barsGap + barsWidth, height);
	return [NSImage imageWithSize:size flipped:NO drawingHandler:^BOOL(NSRect rect) {
		NSFont *font = speedFont();
		NSDictionary *attributes = @{NSFontAttributeName: font, NSForegroundColorAttributeName: [NSColor labelColor]};
		CGFloat line = ceil(font.ascender - font.descender);
		CGFloat middle = height / 2;
		NSSize upSize = [up sizeWithAttributes:attributes];
		NSSize downSize = [down sizeWithAttributes:attributes];
		[up drawAtPoint:NSMakePoint(textWidth - upSize.width, middle - 0.5) withAttributes:attributes];
		[down drawAtPoint:NSMakePoint(textWidth - downSize.width, middle - line + 0.5) withAttributes:attributes];
		NSColor *off = [[NSColor labelColor] colorWithAlphaComponent:0.16];
		for (int row = 0; row < 2; row++) {
			int level = row == 0 ? upLevel : downLevel;
			NSColor *on = row == 0 ? [NSColor colorWithSRGBRed:0.91 green:0.42 blue:0.85 alpha:1] : [NSColor systemBlueColor];
			CGFloat y = row == 0 ? middle + rowGap / 2 : middle - rowGap / 2 - rowHeight;
			for (int i = 0; i < 8; i++) {
				[(i < level ? on : off) setFill];
				NSRect cell = NSMakeRect(textWidth + barsGap + i * (cellWidth + cellGap), y, cellWidth, rowHeight);
				[[NSBezierPath bezierPathWithRoundedRect:cell xRadius:1 yRadius:1] fill];
			}
		}
		return YES;
	}];
}

void speedBarShow(const char *up, const char *down, int upLevel, int downLevel) {
	@autoreleasepool {
		NSString *upText = [NSString stringWithUTF8String:up];
		NSString *downText = [NSString stringWithUTF8String:down];
		NSString *label = [NSString stringWithFormat:@"上传 %@，下载 %@", upText, downText];
		dispatch_async(dispatch_get_main_queue(), ^{
			if (speedItem == nil) {
				speedItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength] retain];
				speedItem.autosaveName = @"speed";
				speedTarget = [[SpeedBarTarget alloc] init];
				speedItem.button.target = speedTarget;
				speedItem.button.action = @selector(clicked:);
			}
			speedItem.button.image = speedBarImage(upText, downText, upLevel, downLevel, [[NSStatusBar systemStatusBar] thickness]);
			speedItem.button.accessibilityLabel = label;
			speedItem.visible = YES;
		});
	}
}

void speedBarHide(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (speedItem != nil) {
			speedItem.visible = NO;
		}
	});
}
