from asciimatics.effects import Print, Matrix
from asciimatics.renderers import ColourImageFile, FigletText, Rainbow
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, StopApplication
from asciimatics.event import KeyboardEvent


# Check for KeyboardEvent == 99, (c)
def global_shortcuts(event):
    if isinstance(event, KeyboardEvent):
        if event.key_code == 99:
            raise StopApplication("Stopped")


# Animate class that handles main ascii art for STEADYHAMMER. Uses hammer.jpeg for image file.
class Animate:
    last_scene = None

    # Prints hammer.jpeg and STEADYHAMMER text to intro screen
    def intro(self, screen):
        effects = [
            Matrix(screen),
            Print(
                screen,
                ColourImageFile(screen, 'hammer.jpeg', bg=0, fill_background=True),
                int(screen.height / 2 - 20), int(screen.width / 2 - 30), transparent=False, speed=0),
            Print(
                screen,
                Rainbow(screen, FigletText("LUCKYHAMMER", font='big')), int(screen.height / 2 + 10),
                int(screen.width / 2 - 40), 1, transparent=False, speed=0
            )

        ]
        scenes = [Scene(effects, -1)]
        screen.play(scenes, stop_on_resize=True, start_scene=self.last_scene, unhandled_input=global_shortcuts)

    # Displays self.intro
    def start(self):
        while True:
            try:
                Screen.wrapper(self.intro)
                break
            except ResizeScreenError as e:
                self.last_scene = e.scene
