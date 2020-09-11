@echo off

set plan_path=%2

echo [[provides]]>>                            %plan_path%
echo name = "some_requirement">>               %plan_path%
echo [[requires]]>>                            %plan_path%
echo name = "some_requirement">>               %plan_path%
echo [requires.metadata]>>                     %plan_path%
echo version = "some_version">>                %plan_path%
echo some_metadata_key = "some_metadata_val">> %plan_path%
