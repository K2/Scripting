Import-Module ShowUI

Function Out-SquarifiedTreeMap
{
    <#
    .SYNOPSIS
        Used to present a Squarified Treemap and optional heatmap for visualizing data.

    .DESCRIPTION
        Used to present a Squarified Treemap and optional heatmap for visualizing data.

    .PARAMETER Width
        Sets the Width of the squarified treemap window

    .PARAMETER Height
        Sets the Height of the squarified treemap window

    .PARAMETER InputObject
        Collection of Data that will be represented in the squarified treemap.
        Accepts pipeline input.

    .PARAMETER LabelProperty
        Determines the Label that can be displayed on the UI in the tooltip.

    .PARAMETER DataProperty
        Used to determine the Size of each item in the squarified treemap. Must be used
        when supplying an object with a property. If passing just values, then this must be
        left blank.

    .PARAMETER HeatmapProperty
        Used when a heatmap will be displayed in squarified treemap by setting the property
        that will be used to determine the color scheme for the UI. If MaxHeatMapSize is not used,
        then the largest value will be used as the threshold.

    .PARAMETER MaxHeatMapSize
        Used to set a threshold to influence the colors of the heatmap. If left blank and HeatMapProperty
        is used, then the largest value for HeatMapProperty will be used as the threshold.

    .PARAMETER ToolTip
        Custom tooltip that will apply to UI. Each square/rectangle will have a tooltip
        which will appear when mouse is over the object. This must be a scriptblock that 
        contains a here-string. The use of $This is allowed and contains the following 
        available properties:

        LabelProperty
        DataProperty
        HeatmapProperty
        Row
        Orientation
        Width
        Height
        Coordinate
        ObjectData (This contains the object that was passed to this function)

    .PARAMETER ShowLabel
        Custom label that will apply to rectangle in the UI. This must be a scriptblock that 
        contains a here-string. The use of $This is allowed and contains the following 
        available properties:

        LabelProperty
        DataProperty
        HeatmapProperty
        Row
        Orientation
        Width
        Height
        Coordinate
		ObjectData (This contains the object that was passed to this function)
		
    .PARAMETER PassThru
        Allows you to select a single item on the treemap that will close out the UI and output the corresponding
        original object based on the selected item for use with another command.

        You can move this UI around as long as you are holding down on the CTRL key prior to left clicking on the UI and 
        then drag it around. This will prevent the UI from closing and the object being presented.
        
    .NOTES
        Name:  Out-SquarifiedTreeMap
        Author: Boe Prox
        Version History:
            1.3 //Boe Prox - 11/08/2016
                -Updated ShowLable to accept scriptblock for more customizable labels
            1.2 //Boe Prox - 10/31/2016
                -Allowed for displaying a label on the UI
            1.1 //Boe Prox - 10/28/2016
                -Removed runspaces to allow piping of data from UI into another command
                -Allowed for selecting of a single item to output original object
            1.0 //Boe Prox - 12/07/2015
                -Production Version
    .EXAMPLE
        1..8|Out-SquarifiedTreeMap -Width 600 -Height 200 -MaxHeatMapSize 8 -ShowLabel HeatmapProperty

        Description
        -----------
        Creates a squarified treemap with a heat map with incoming data. A MaxHeatMapSize of 
        15 was set to ensure an accurate heatmap is displayed with the given data. The size of 
        the UI was also set as well.

    .EXAMPLE
        $Tooltip = {
        @"
    Process Name <PID>:   $($This.LabelProperty) <$($This.ObjectData.Id)>     
    WorkingSet Memory(MB): $([math]::Round(($This.DataProperty/1MB),2))
"@
        }
        Get-Process | Sort-Object -prop WS -Descending | Select -First 8 | 
        Out-SquarifiedTreeMap -Tooltip $Tooltip -LabelProperty ProcessName -DataProperty WS -HeatmapProperty WS -Width 600 -Height 400 `
        -PassThru -ShowLabel {"$($This.LabelProperty) <$($This.ObjectData.ID)>"} | 
        Stop-Process -WhatIf

        Description
        -----------
        A Squarified Treemap with a heat map is created of all running processes. To support the default tooltip,
        the LabelProperty was chosen with the ProcessName. The DataProperty was used with WS for the sizing of the 
        squares in the UI based on memory. The same property is used for the Heatmap to help show the largest and 
        smallest consumer of memory. Upon clicking one of the items on the UI, it will output the original object
        so it can be used in another command as the -PassThru parameter was used.

    .EXAMPLE
        $FileInfo = Get-ChildItem -Directory|ForEach {
            $Files = Get-ChildItem $_.fullname -Recurse -File|measure-object -Sum -Property length
            [pscustomobject]@{
                Name = $_.name
                Fullname = $_.fullname
                Count = [int64]$Files.Count
                Size = [int64]$Files.Sum
            }
        }

        $Tooltip = {
        @"
        Name = $($This.LabelProperty)
        Fullname = $($This.ObjectData.FullName)
        FileCount = $($This.Dataproperty)
        Size = $([math]::round(($This.HeatmapProperty/1MB),2)) MB
"@
        }

        $FileInfo | 
        Out-SquarifiedTreeMap -Width 800 -Height 600 -LabelProperty Name `
        -DataProperty Count -HeatmapProperty Size -ToolTip $Tooltip -ShowLabel LabelProperty -PassThru     

        Description
        -----------
        A Squarified Treemap with a heat map is created of folder sizes. First a command is run to
        determine the sizes of a set of folders and then a custom ToolTip is created using a scriptblock
        with a here-string within it. The use of $This is shown with using LabelProperty, DataProperty and
        HeatMapProperty to better display the data when the mouse is hovering over each square.

    #>	
	Param (
		[float]$Width = 600,
		[float]$Height = 200,
		[parameter(ValueFromPipeline = $True)]
		[object[]]$InputObject = @(60, 60),
		[ValidateNotNullorEmpty()]
		[string]$LabelProperty,
		[ValidateNotNullorEmpty()]
		[string]$DataProperty,
		[ValidateNotNullorEmpty()]
		[string]$HeatmapProperty,
		[ValidateNotNullorEmpty()]
		[int64]$MaxHeatMapSize,
		[scriptblock]$ToolTip,
		[scriptblock]$ShowLabel,
		[switch]$PassThru
	)
	Begin
	{
		Write-Verbose "[BEGIN]Starting Function"
		#region Helper Functions        
		Function New-SquareTreeMapData
		{
			[cmdletbinding()]
			Param (
				[float]$Width,
				[float]$Height,
				[parameter(ValueFromPipeline = $True)]
				[object[]]$InputObject,
				[string]$LabelProperty,
				[string]$DataProperty,
				[string]$HeatmapProperty,
				[int64]$MaxHeatMapSize
			)
			Begin
			{
				Try
				{
					[void][treemap.coordinate]
				}
				Catch
				{
					Add-Type -TypeDefinition @"
                        using System;
                        namespace TreeMap
                        {
                            public class Coordinate
                            {
                                public float X;
                                public float Y;

                                public Coordinate(float x, float y)
                                {
                                    X = x;
                                    Y = y;
                                }
                                public Coordinate(float x)
                                {
                                    X = x;
                                    Y = 0;
                                }
                                public Coordinate()
                                {
                                    X = 0;
                                    Y = 0;
                                }
                                public override string ToString()
                                {
                                    return X+","+Y;
                                } 
                            }
                        }
"@
				}
				Function Get-StartingOrientation
				{
					Param ([float]$Width,
						[float]$Height)
					Switch (($Width -ge $Height))
					{
						$True { 'Vertical' }
						$False { 'Horizontal' }
					}
				}
				
				#region Starting Data
				$Tag = 1
				$Row = 1
				$Rectangle = New-Object System.Collections.ArrayList
				$DecimalThreshold = .4
				$TempData = New-Object System.Collections.ArrayList
				If ($PSBoundParameters.ContainsKey('InputObject'))
				{
					$Pipeline = $False
					Write-Verbose "Adding `$InputObject to list"
					[void]$TempData.AddRange($InputObject)
				}
				Else
				{
					$Pipeline = $True
				}
				#Sort the data
				$List = New-Object System.Collections.ArrayList
				$Stack = New-Object System.Collections.Stack
				$FirstCoordRun = $True
				$CurrentX = 0
				$CurrentY = 0
				#endregion Starting Data
			}
			Process
			{
				If ($Pipeline)
				{
					#Write-Verbose "Adding $($_) to list"
					[void]$TempData.Add($_)
				}
			}
			End
			{
				If ($PSBoundParameters.ContainsKey('DataProperty'))
				{
					$TempData | Sort-Object $DataProperty | ForEach {
						#If it is 0, then it should not occupy space
						If ($_.$DataProperty -gt 0)
						{
							$Stack.Push($_)
						}
					}
				}
				Else
				{
					$TempData | Sort-Object | ForEach {
						#If it is 0, then it should not occupy space
						If ($_ -gt 0)
						{
							$Stack.Push($_)
						}
					}
				}
				$ElementCount = $Stack.Count
				#Begin building out the grid
				$Temp = New-Object System.Collections.ArrayList
				
				While ($Stack.Count -gt 0)
				{
					$PreviousWidth = 0
					$PreviousHeight = 0
					$TotalBlockHeight = 0
					$TotalBlockWidth = 0
					Write-Verbose "Width: $Width - Height: $Height"
					#Write-Verbose "StackCount: $($Stack.Count)"
					$FirstRun = $True
					#Write-Verbose "Row: $Row"
					If ($PSBoundParameters.ContainsKey('DataProperty'))
					{
						$TotalArea = ($Stack | Measure-Object -Property $DataProperty -Sum).Sum
					}
					Else
					{
						$TotalArea = ($Stack | Measure-Object -Sum).Sum
					}
					#Write-Verbose 'Getting starting orientation'
					$Orientation = Get-StartingOrientation -Width $Width -Height $Height
					Write-Verbose "Orientation: $Orientation"
					$Iteration = 0
					Do
					{
						$Iteration++
						#Write-Verbose "Iteration: $Iteration"
						#Write-Verbose "TotalArea: $($TotalArea)"
						[void]$List.Add($Stack.Pop())
						If ($PSBoundParameters.ContainsKey('DataProperty'))
						{
							$PercentArea = (($List | Measure-Object -Property $DataProperty -Sum).Sum/$TotalArea)
						}
						Else
						{
							$PercentArea = (($List | Measure-Object -Sum).Sum/$TotalArea)
						}
						#Write-Verbose "PercentArea: $($PercentArea)"
					}
					Until (($PercentArea -ge $DecimalThreshold) -OR ($Stack.Count -eq 0))
					#Write-Verbose "Threshold met!"
					If ($List.Count -gt 1)
					{
						If ($PSBoundParameters.ContainsKey('DataProperty'))
						{
							$_area = ($List | Measure-Object -Property $DataProperty -Sum).Sum
						}
						Else
						{
							$_area = ($List | Measure-Object -Sum).Sum
						}
					}
					$List | ForEach {
						
						If ($PSBoundParameters.ContainsKey('DataProperty'))
						{
							$Item = $_.$DataProperty
						}
						Else
						{
							$Item = $_
						}
						If ($PSBoundParameters.ContainsKey('LabelProperty'))
						{
							$Label = $_.$LabelProperty
						}
						If ($PSBoundParameters.ContainsKey('HeatmapProperty'))
						{
							$HeatmapData = $_.$HeatmapProperty
						}
						ElseIf ($PSBoundParameters.ContainsKey('MaxHeatMapSize'))
						{
							$HeatmapData = $_
						}
						Switch ($Orientation)
						{
							'Vertical' {
								#Get block width
								$BlockWidth = ($PercentArea * $Width)
								Write-Verbose "BlockWidth: $($BlockWidth)"
								If ($Iteration -eq 1)
								{
									$BlockHeight = $Height
								}
								Else
								{
									#Get block height
									$_percentarea = ($Item / $_area)
									$BlockHeight = ($_percentarea * $Height)
									Write-Verbose "BlockHeight: $($BlockHeight)"
								}
							}
							'Horizontal' {
								#Get block height
								$BlockHeight = ($PercentArea * $Height)
								Write-Verbose "BlockHeight: $($BlockHeight)"
								If ($Iteration -eq 1)
								{
									$BlockWidth = $Width
								}
								Else
								{
									#Get block width
									$_percentarea = ($Item / $_area)
									$BlockWidth = ($_percentarea * $Width)
									Write-Verbose "BlockWidth: $($BlockWidth)"
								}
							}
						}
						If ($FirstCoordRun)
						{
							Write-Verbose 'First run coordinates'
							$Coordinate = New-Object -Typename treemap.coordinate -ArgumentList $CurrentX, $CurrentY
							$FirstCoordRun = $False
						}
						Else
						{
							Write-Verbose 'Rest of coordinates'
							Switch ($Orientation)
							{
								'Vertical' {
									Write-Verbose 'Setting Vertical coordinates'
									Write-Verbose "TotalHeight: $($TotalBlockHeight)"
									$Y = $TotalBlockHeight + $CurrentY
									$Coordinate = New-Object -Typename treemap.coordinate -ArgumentList $CurrentX, $Y
								}
								'Horizontal' {
									Write-Verbose "TotalWidth: $($TotalBlockWidth)"
									Write-Verbose 'Setting Horizontal coordinates'
									$X = $TotalBlockWidth + $CurrentX
									$Coordinate = New-Object -Typename treemap.coordinate -ArgumentList $X, $CurrentY
								}
							}
						}
						[pscustomobject]@{
							Tag			     = $Tag
							LabelProperty    = $Label
							DataProperty	 = $Item
							HeatmapProperty  = $HeatmapData
							Row			     = $Row
							Orientation	     = $Orientation
							Width		     = $BlockWidth
							Height		     = $BlockHeight
							Coordinate	     = $Coordinate
							ObjectData	     = $_
						}
						$Tag++
						$PreviousWidth = $BlockWidth
						$PreviousHeight = $BlockHeight
						$TotalBlockHeight = $TotalBlockHeight + $BlockHeight
						$TotalBlockWidth = $TotalBlockWidth + $BlockWidth
					}
					If ($Orientation -eq 'Vertical')
					{
						$CurrentX = $BlockWidth + $CurrentX
						$Width = $Width - $BlockWidth
					}
					Else
					{
						$CurrentY = $CurrentY + $BlockHeight
						$Height = $Height - $BlockHeight
					}
					Write-Verbose "CurrentX: $($CurrentX)"
					Write-Verbose "CurrentY: $($CurrentY)"
					$list.Clear()
					$Row++
					$FirstCoordRun = $True
				}
			}
		}
		Function Color
		{
			Param ($Decimal)
			if($Decimal -eq 0.0) {
				Return ([windows.media.color]::FromRgb(0, 0, 255)).ToString()
			} 
			If ($Decimal -gt 1)
			{
				$Decimal = 1
			}
			$Red = ([float](2.0) * $Decimal)
			$Red = If ($Red -gt 1)
			{
				255
			}
			Else
			{
				$Red * 255
			}
			$Green = (([float](2.0) * (1 - $Decimal)))
			$Green = If ($Green -gt 1)
			{
				255
			}
			Else
			{
				$Green * 255
			}
			([windows.media.color]::FromRgb($Red, $Green, 0)).ToString()
		}
		Function New-Rectangle
		{
			Param (
				$Width,
				$Height,
				$Color,
				$Tooltip,
				$Tag
			)
			$Rectangle = new-object System.Windows.Shapes.Rectangle
			$Rectangle.Width = $Width
			$Rectangle.Height = $Height
			$Rectangle.Fill = $Color
			$Rectangle.Stroke = 'Black'
			$Rectangle.ToolTip = $Tooltip
			$Rectangle.Tag = $Tag
			Return $Rectangle
		}
		Function New-ViewBox
		{
			Param (
				$Width,
				$Height,
				$Text
			)
			$Label = new-object System.Windows.Controls.Label
			$Viewbox = new-object System.Windows.Controls.Viewbox
			$DropShadow = New-Object System.Windows.Media.Effects.DropShadowEffect
			$DropShadow.Opacity = 5
			$DropShadow.BlurRadius = 5
			$DropShadow.Color = 'Black'
			$DropShadow.ShadowDepth = 0
			$Viewbox.Stretch = 'Uniform'
			$Viewbox.Width = $Width
			$Viewbox.Height = $Height
			$Label.IsHitTestVisible = $False
			$Label.FontFamily = 'Calibri'
			$Label.FontWeight = 'Bold'
			$Label.Foreground = 'White'
			$Label.Content = $Text
			$Label.Effect = $DropShadow
			$Viewbox.AddChild($Label)
			Return $Viewbox
		}
		#endregion Helper Functions
		
		$TempData = New-Object System.Collections.ArrayList
		If ($PSBoundParameters.ContainsKey('InputObject'))
		{
			$Pipeline = $False
			Write-Verbose "Adding `$InputObject to list"
			[void]$TempData.AddRange($InputObject)
		}
		Else
		{
			$Pipeline = $True
		}
		Write-Verbose "[BEGIN] End Begin"
	}
	Process
	{
		Write-Verbose "[PROCESS]"
		If ($Pipeline)
		{
			Write-Verbose "Adding $($_) to list"
			[void]$TempData.Add($_)
		}
	}
	End
	{
		Write-Verbose "[END] Begin End"
		#region  Hashtables 
		$DataHash = [hashtable]::Synchronized(@{
				Width   = $Width
				Height  = $Height
			})
		#endregion  Hashtables
		If ($PSBoundParameters.ContainsKey('PassThru'))
		{
			[void]$PSBoundParameters.Remove('PassThru')
			$Script:IsPassThru = $True
		}
		Else
		{
			$Script:IsPassThru = $False
		}
		Write-Verbose "[PassThruBoundParam] $($Script:IsPassThru)"
		If ($PSBoundParameters.ContainsKey('ShowLabel'))
		{
			[void]$PSBoundParameters.Remove('ShowLabel')
			$Script:ShowLabel = $True
			$DataHash['ShowLabel'] = $ShowLabel
		}
		Else
		{
			$Script:ShowLabel = $False
		}
		If (-NOT $PSBoundParameters.ContainsKey('Width'))
		{
			$PSBoundParameters['Width'] = $Width
		}
		If (-NOT $PSBoundParameters.ContainsKey('Height'))
		{
			$PSBoundParameters['Height'] = $Height
		}
		If ($PSBoundParameters.ContainsKey('ToolTip'))
		{
			[void]$PSBoundParameters.Remove('ToolTip')
			$HasToolTip = $True
			$DataHash['ToolTip'] = $ToolTip
		}
		Else
		{
			$HasToolTip = $False
		}
		$DataHash['HasToolTip'] = $HasToolTip
		$PSBoundParameters['InputObject'] = $TempData
		If ($PSBoundParameters.ContainsKey('PipelineVariable'))
		{
			[void]$PSBoundParameters.Remove('PipelineVariable')
		}
		$TreeMapData = New-SquareTreeMapData @PSBoundParameters
		$DataHash['TreeMapData'] = $TreeMapData
		If ($PSBoundParameters.ContainsKey('HeatmapProperty'))
		{
			$Maximum = ($TreeMapData | Measure-Object -Property HeatmapProperty -Maximum).Maximum
			$DataHash['HeatmapProperty'] = $HeatmapProperty
			$DataHash['Maximum'] = $Maximum
		}
		If ($PSBoundParameters.ContainsKey('MaxHeatMapSize'))
		{
			$Maximum = $MaxHeatMapSize
			$DataHash['MaxHeatMapSize'] = $MaxHeatMapSize
			$DataHash['Maximum'] = $Maximum
		}
		
		#region XAML
		[xml]$xaml = @"
        <UserControl 
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
            x:Name="Window" 
			>
			<Viewbox >
				<Canvas MinWidth = "$($DataHash.Width)" MinHeight = "$($DataHash.Height)" 
				x:Name="Canvas" />
			</Viewbox>
        </UserControl>
"@
		#endregion XAML
		
		#region Connect to Control 
		$reader = (New-Object System.Xml.XmlNodeReader $xaml)
		$Window = [System.Windows.Markup.XamlReader]::Load($reader)
		$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach {
			New-Variable -Name $_.Name -Value $Window.FindName($_.Name) -Force -ErrorAction SilentlyContinue -Scope Script
		}
		#endregion Connect to Control 
		$Window.Add_MouseLeftButtonDown({
				$Script:KeyDown = [System.Windows.Input.Keyboard]::IsKeyDown("RightCtrl") -OR [System.Windows.Input.Keyboard]::IsKeyDown("LeftCtrl")
				Write-Verbose "[MouseButtonDown-CTRLKeyDown] $($Script:KeyDown)"
				Write-Verbose "[IsPassThru] $($Script:IsPassThru)"
				If ($_.OriginalSource -is [System.Windows.Shapes.Rectangle])
				{
					$Tooltip = {
@"
Name = $($This.LabelProperty)
FullName = $($This.ObjectData.FullName)
PercentValid = $($This.ObjectData.PercentValid)
Size = $($This.ObjectData.Size) 
"@
}
					$Source = $_.OriginalSource
					$Script:Result = $DataHash.TreeMapData | Where {
						$_.Tag -eq $Source.Tag
					} | Select-Object -ExpandProperty ObjectData
					Out-SquarifiedTreeMap -InputObject $Script:Result.Children -Width $Width -Height $Height -DataProperty Size -HeatmapProperty Heat -MaxHeatMapSize 1.0 -LabelProperty Label -ToolTip $Tooltip -ShowLabel {"$($This.ObjectData.Label)"}  | Show-UI
				}
			})
		
		#region TabControl event handler
		<# 
		#region Control Events
		$Window.Add_MouseRightButtonUp({
				$This.close()
			})
		[System.Windows.RoutedEventHandler]$Global:RectangleKeyDownChangeHandler = {
			Write-Verbose "[KeyDwnhandler-CTRLKeyDown] $($Script:KeyDown)"
			If ($Script:KeyDown)
			{
				Try
				{
					Write-Verbose "[KEYUP] DragMove"
					$Window.DragMove()
				}
				Catch { }
			}
		}
		$Window.AddHandler([System.Windows.Shapes.Rectangle]::MouseLeftButtonUpEvent, $RectangleKeyDownChangeHandler)
		
		[System.Windows.RoutedEventHandler]$Global:RectangleKeyUpChangeHandler = {
			If (-NOT $Script:KeyDown)
			{
				If ($_.OriginalSource -is [System.Windows.Shapes.Rectangle])
				{
					$Source = $_.OriginalSource
					$Script:Result = $DataHash.TreeMapData | Where {
						$_.Tag -eq $Source.Tag
					} | Select-Object -ExpandProperty ObjectData
					#$Canvas.Children.Clear()
					#New-SquareTreeMapData -InputObject $Script:Result 
					Show-UI Out-SquarifiedTreeMap -InputObject $Script:Result.Children -Verbose -Width 600 -Height 200 -DataProperty Count -HeatmapProperty Data -LabelProperty Label  
					#$Canvas.InvalidateVisual()
					#$Window.Close()
				}
			}
		} 
		$Window.AddHandler([System.Windows.Shapes.Rectangle]::MouseLeftButtonUpEvent, $RectangleKeyUpChangeHandler)
		#>
		#endregion TabControl event handler
		#endregion Control Events
		
		#region Begin building the Squarified Tree Map
		$DataHash.TreeMapData | ForEach {
			$This = $_
			If ($DataHash.ContainsKey('HeatmapProperty'))
			{
				$Decimal = $_.HeatmapProperty / $DataHash.Maximum
				$Color = (Color -Decimal $Decimal)
			}
			ElseIf ($DataHash.ContainsKey('MaxHeatMapSize'))
			{
				$Decimal = $_.HeatmapProperty / $DataHash.Maximum
				$Color = (Color -Decimal $Decimal)
			}
			Else
			{
				Write-Verbose 'Default color used'
				$Color = 'Green'
			}
			Write-Verbose "Color: $($Color)"
			Write-Verbose "Creating Rectangle for $($_.Data)"
			If (-NOT $DataHash.HasToolTip)
			{
				$__Tooltip = @"   
Label:   $($This.LabelProperty)     
Data:    $($This.DataProperty)
HeatMap: $($This.HeatmapProperty)
"@
			}
			Else
			{
				#Scope gets weird after setting the variable in a new runspace so we 
				#need to update the scriptblock -- Might not be needed after removing runspaces
				$ToolTip = [scriptblock]::Create($DataHash.ToolTip.ToString())
				$__Tooltip = $ToolTip.Invoke() | Out-String
			}
			$Rectangle = New-Rectangle -Width $_.Width -Height $_.Height -Color $Color -Tooltip $__Tooltip -Tag $_.Tag
			[void]$Canvas.Children.Add($Rectangle)
			[System.Windows.Controls.Canvas]::SetLeft($Rectangle, $_.Coordinate.X)
			[System.Windows.Controls.Canvas]::SetTop($Rectangle, $_.Coordinate.Y)
			If ($ShowLabel)
			{
				$ShowLabel = [scriptblock]::Create($DataHash.ShowLabel.ToString())
				$__ShowLabel = $ShowLabel.Invoke() | Out-String
				$Viewbox = New-ViewBox -Width $_.Width -Height $_.Height -Text $__ShowLabel
				[void]$Canvas.Children.Add($Viewbox)
				[System.Windows.Controls.Canvas]::SetLeft($Viewbox, $_.Coordinate.X)
				[System.Windows.Controls.Canvas]::SetTop($Viewbox, $_.Coordinate.Y)
			}
		}
		#endregion Begin building the Squarified Tree Map
		
		#Show UI
		Write-Verbose "[END] Show UI"
		$Window | Show-Window
		Write-Verbose "[END] UI Close"
		If ($IsPassThru)
		{
			Write-Verbose "Output Object"
			$Result
		}
	}
}